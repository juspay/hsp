{
  description = "hsp-testprog: a GHC program with a known shape, for hsp's live tests";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    haskell-flake.url = "github:srid/haskell-flake";
  };
  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];
      imports = [ inputs.haskell-flake.flakeModule ];
      perSystem = { self', pkgs, lib, ... }:
        let
          # One project per GHC: hsp reads RTS structures whose layout changes
          # between releases (StgTSO gained a word in 9.10), so the live tests
          # run against each.  ghc984 is pinned (a version services run in
          # production); ghc98 / ghc910 follow nixpkgs' latest 9.8 / 9.10, to
          # catch a minor release that moves something.
          project = ghcPackages: {
            projectRoot = ./.;
            basePackages = ghcPackages;
            # keep .symtab and DWARF: hsp names code from them
            settings.hsp-testprog = { strip = false; };
            devShell.enable = false;
            autoWire = [ "packages" ];
          };
        in
        {
          haskellProjects.ghc984 = project pkgs.haskell.packages.ghc984;
          haskellProjects.ghc98 = project pkgs.haskell.packages.ghc98;
          haskellProjects.ghc910 = project pkgs.haskell.packages.ghc910;
          packages.default = self'.packages.ghc910-hsp-testprog;
        };
    };
}
