# Doc for nix-ld: https://github.com/nix-community/nix-ld
# https://github.com/mcdonc/.nixconfig/blob/master/videos/pydev/script.rst
# https://www.youtube.com/watch?v=7lVP4NJWJ9g
# https://github.com/Mic92/dotfiles/blob/main/machines/modules/fhs-compat.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix/monthly";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, fenix, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { 
        inherit system; 
        overlays = [ fenix.overlays.default ];
      };

      # libPath = with pkgs; lib.makeLibraryPath [
      #   stdenv.cc.cc
      #   openssl
      # ];

      clangVersion = "19";
    in 
    {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = [
          (pkgs.fenix.complete.withComponents [
              "cargo"
              "clippy"
              "rust-src"
              "rustc"
              "rustfmt"
              "miri"
          ])
          pkgs.cargo-show-asm
          pkgs.cargo-expand
          pkgs.cargo-flamegraph
          pkgs.cargo-valgrind
          pkgs.cargo-fuzz
          pkgs.cargo-pgo

          pkgs.rust-analyzer-nightly
          pkgs.openssl
          pkgs.pkg-config

          pkgs."clang_${clangVersion}"
          pkgs."llvmPackages_${clangVersion}".bintools
          pkgs."bolt_${clangVersion}"
          pkgs.cmake
          pkgs.rustfilt
        ];

        # RUSTFLAGS = "-C link-arg=-Wl,-dynamic-linker,/lib64/ld-linux-x86-64.so.2";

        # LD_LIBRARY_PATH = libPath;
        shellHook = ''
          export LD_LIBRARY_PATH=$NIX_LD_LIBRARY_PATH
        '';

        LIBCLANG_PATH = pkgs.lib.makeLibraryPath [ pkgs."llvmPackages_${clangVersion}".libclang.lib ];
      };
    };
}
