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
      devShells.${system}.default = pkgs.mkShell {
        nativeBuildInputs = tools ++ [ pkgs.gcc ];
        buildInputs = deps;
        CLANG = bpfClang;
      };
    };
}
