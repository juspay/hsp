{
  description = "hsp: sampling profiler for GHC programs";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    process-compose-flake.url = "github:Platonic-Systems/process-compose-flake";
    services-flake.url = "github:juspay/services-flake";
  };
  outputs = { self, nixpkgs, process-compose-flake, services-flake }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      deps = [ pkgs.libbpf pkgs.elfutils pkgs.curl pkgs.zstd ];
      # the BPF target needs the unwrapped clang: nix's wrapper adds x86-only
      # hardening flags (-fzero-call-used-regs) that clang rejects for bpf
      bpfClang = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
      tools = [ pkgs.pkg-config pkgs.bpftools ];
      hsp = self.packages.${system}.default;

      # The test program (tests/testprog) on GHC 9.8.4, with the flags a
      # service needs and nothing stripped, and its map: what the VM test runs.
      testprog = pkgs.haskell.lib.overrideCabal
        (pkgs.haskell.packages.ghc984.callCabal2nix "hsp-testprog" ./tests/testprog { })
        (_: { dontStrip = true; enableSeparateBinOutput = false; doHaddock = false; });
      testmap = pkgs.runCommand "hsp-testprog-map" { } ''
        mkdir -p $out/maps $out/smoke/build/ghc984
        ${hsp}/bin/hsp symmap ${testprog}/bin/hsp-testprog --install $out/maps
        ln -s ${testprog}/bin/hsp-testprog $out/smoke/build/ghc984/hsp-testprog
        ln -s $out/maps/*.hsm $out/smoke/build/ghc984/testprog.hsm
      '';

      # The UI stack (stack/stack.nix) through services-flake, without
      # flake-parts: process-compose-flake's lib evaluates the modules.
      pcLib = import process-compose-flake.lib { inherit pkgs; };
      mkStack = name: ports: pcLib.makeProcessCompose {
        inherit name;
        modules = [
          services-flake.processComposeModules.default
          (import ./stack/stack.nix ({ inherit hsp; } // ports))
        ];
      };
      # run it in a state directory, so ./data and ./maps have a home
      stackApp = name: ports: {
        type = "app";
        program = toString (pkgs.writeShellScript "${name}-run" ''
          D="''${HSP_STACK_DIR:-$HOME/.local/share/${name}}"
          mkdir -p "$D" && cd "$D"
          echo "${name}: Grafana http://127.0.0.1:${toString ports.grafanaPort}  Pyroscope http://127.0.0.1:${toString ports.pyroscopePort}  collector http://127.0.0.1:${toString ports.collectPort}  (maps: ''${HSP_MAPS:-$D/maps}; state: $D)"
          exec ${mkStack name ports}/bin/${name} "$@"
        '');
      };
    in {
      packages.${system}.default = pkgs.stdenv.mkDerivation {
        pname = "hsp";
        version = "0.2.0";
        src = ./.;
        nativeBuildInputs = tools;
        buildInputs = deps;
        makeFlags = [ "PREFIX=$(out)" "CLANG=${bpfClang}" ];
        doCheck = true;
        checkTarget = "test";
      };
      apps.${system} = {
        stack = stackApp "hsp-stack" { grafanaPort = 3300; pyroscopePort = 4040; collectPort = 4041; };
        # a second instance on other ports (a test beside a running stack)
        stack-alt = stackApp "hsp-stack-alt" { grafanaPort = 3301; pyroscopePort = 4050; collectPort = 4051; };
      };
      # NixOS: services.hsp.collect on the collector host, services.hsp.agents.<comm>
      # on every service host (nix/module.nix); the package defaults to this flake's.
      nixosModules.default = { ... }: {
        imports = [ ./nix/module.nix ];
        services.hsp.package = nixpkgs.lib.mkDefault hsp;
      };
      # an example host with both, evaluated by `nix flake check`
      nixosConfigurations.example = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          self.nixosModules.default
          ({ modulesPath, ... }: {
            imports = [ "${modulesPath}/profiles/minimal.nix" ];
            boot.loader.grub.enable = false;
            fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
            system.stateVersion = "25.11";
            services.hsp.collect = { enable = true; pyroscope = "http://pyroscope.internal:4040"; openFirewall = true; };
            services.hsp.agents.euler-api-txns = { collector = "http://127.0.0.1:4041"; };
            services.hsp.agents.euler-webservice = { collector = "http://127.0.0.1:4041"; hz = 19; labelMode = "full"; extraArgs = [ "-d" "256" ]; };
          })
        ];
      };
      checks.${system} = let ex = self.nixosConfigurations.example.config.systemd; in {
        package = hsp;
        # The end-to-end test, no root needed on the developer's machine: a
        # NixOS VM with the module (collector + an agent as the hsp user with
        # its three capabilities) and the test program.  Offline path:
        # tests/smoke.sh (record, fold, its assertions).  Continuous path: the
        # unit's agent finds the program, the collector resolves by the map's
        # id and dumps folded text; the names must be source names.
        #   nix build .#checks.x86_64-linux.e2e -L      (or make e2e)
        e2e = pkgs.testers.runNixOSTest {
          name = "hsp-e2e";
          nodes.machine = { pkgs, ... }: {
            imports = [ self.nixosModules.default ];
            environment.systemPackages = [ hsp testprog pkgs.python3 pkgs.curl ];
            services.hsp.collect = { enable = true; listen = "127.0.0.1:4041"; mapsDir = "${testmap}/maps"; dumpDir = "/var/lib/hsp/dump"; };
            services.hsp.agents.hsp-testprog = { collector = "http://127.0.0.1:4041"; interval = 2; hz = 499; labelMode = "full"; };
            virtualisation.cores = 2;
            virtualisation.memorySize = 2048;
          };
          testScript = ''
            machine.wait_for_unit("hsp-collect.service")
            machine.wait_for_open_port(4041)
            machine.wait_for_unit("hsp-agent-hsp-testprog.service")
            machine.wait_until_succeeds("journalctl -u hsp-agent-hsp-testprog | grep -q 'waiting'")

            # continuous: the module's agent (hsp user, three capabilities) finds
            # the program once it starts, the collector resolves by the map's id
            machine.succeed("systemd-run --unit=testprog ${testprog}/bin/hsp-testprog smoke 6")
            machine.wait_until_succeeds("curl -s 127.0.0.1:4041/stats | grep -qE 'received [1-9]'", timeout=60)
            machine.wait_until_fails("systemctl is-active testprog", timeout=60)
            stats = machine.succeed("curl -s 127.0.0.1:4041/stats")
            print(stats)
            assert "rejected 0 " in stats, "the collector rejected batches"
            assert "${testmap}/maps/" in stats, "the map was not found by the binary's id"
            names = machine.succeed("cat /var/lib/hsp/dump/*-hsp-testprog.txt")
            assert "Main.chatty;" in names, "no source names in the collector's output"
            raw = [l for l in names.splitlines() if "_info" in l and "stg_" not in l]
            assert not raw, "raw info-table names in the output: " + "\\n".join(raw[:5])
            assert machine.succeed("ps -o user= -C hsp | sort -u").strip() == "hsp", "hsp does not run as the hsp user"
            metrics = machine.succeed("cat /var/lib/hsp/metrics/hsp-agent-hsp-testprog.prom")
            assert "hsp_agent_batches_sent_total" in metrics
            machine.succeed("systemctl stop hsp-agent-hsp-testprog")   # it would attach to the smoke run below too

            # offline: record + fold + the smoke assertions, as root
            machine.succeed("mkdir -p /tmp/t/smoke/build && cp ${./tests/smoke.sh} /tmp/t/smoke.sh && cp -rL ${testmap}/smoke/build/ghc984 /tmp/t/smoke/build/ && chmod -R u+w /tmp/t")
            print(machine.succeed("cd /tmp/t && HSP=${hsp}/bin/hsp HSP_SMOKE_COST_NS=20000 bash smoke.sh ghc984 2 499 2>&1"))
            print(machine.succeed("journalctl -u hsp-agent-hsp-testprog --no-pager | tail -5"))
          '';
        };
        # the units the module generates, as files: evaluation is the test, no system build
        nixos-module = pkgs.writeTextDir "units" (nixpkgs.lib.concatStringsSep "\n\n" (map (u: "== ${u}\n" + ex.units."${u}".text)
          [ "hsp-collect.service" "hsp-agent-euler-api-txns.service" "hsp-agent-euler-webservice.service" ]));
      };
      devShells.${system}.default = pkgs.mkShell {
        nativeBuildInputs = tools ++ [ pkgs.gcc ];
        buildInputs = deps;
        CLANG = bpfClang;
      };
    };
}
