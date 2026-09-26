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
      deps = [ pkgs.libbpf pkgs.elfutils pkgs.curl ];
      # the BPF target needs the unwrapped clang: nix's wrapper adds x86-only
      # hardening flags (-fzero-call-used-regs) that clang rejects for bpf
      bpfClang = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
      tools = [ pkgs.pkg-config pkgs.bpftools ];
      hsp = self.packages.${system}.default;

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
