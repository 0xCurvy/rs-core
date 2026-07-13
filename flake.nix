{
    description = "rs-core development environment";

    inputs = {
      nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

      rust-overlay.url = "github:oxalica/rust-overlay";
      rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    };

    outputs =
      {
        nixpkgs,
        rust-overlay,
        ...
      }:
      let
        systems = [
          "x86_64-linux"
          "aarch64-linux"
          "aarch64-darwin"
          "x86_64-darwin"
        ];

        forAllSystems = nixpkgs.lib.genAttrs systems;
      in
      {
        devShells = forAllSystems (
          system:
          let
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ (import rust-overlay) ];
            };

            rustToolchain = pkgs.rust-bin.stable."1.96.0".default.override {
              extensions = [
                "clippy"
                "rust-src"
                "rustfmt"
              ];
            };

            nativeLibraries = [
              pkgs.llvmPackages.libclang.lib
              pkgs.libffi
            ];
          in
          {
            default = pkgs.mkShell {
              packages = [
                rustToolchain
                pkgs.llvmPackages.clang
                pkgs.llvmPackages.libclang
                pkgs.libffi
                pkgs.protobuf
                pkgs.pkg-config
                pkgs.cmake
                pkgs.git
              ];

              LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
              LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath nativeLibraries;
              DYLD_LIBRARY_PATH = pkgs.lib.makeLibraryPath nativeLibraries;
              PROTOC = "${pkgs.protobuf}/bin/protoc";
            };
          }
        );
      };
  }