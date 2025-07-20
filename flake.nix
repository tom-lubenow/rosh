{
  description = "Rosh development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    crate2nix = {
      url = "github:nix-community/crate2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nix-github-actions = {
      url = "github:nix-community/nix-github-actions";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      fenix,
      flake-utils,
      crate2nix,
      nix-github-actions,
    }:
    let
      systemOutputs = flake-utils.lib.eachDefaultSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          # Get the Fenix toolchain
          toolchain = fenix.packages.${system}.stable.toolchain;

          # Platform-specific dependencies
          platformDeps =
            with pkgs;
            if stdenv.isDarwin then
              [
                libiconv
              ]
            else
              [
                # Linux-specific dependencies
                openssl
                pkg-config
              ];

          # Generate Cargo.nix
          cargoNix = pkgs.callPackage ./Cargo.nix {
            inherit pkgs;
            buildRustCrateForPkgs =
              pkgs:
              pkgs.buildRustCrate.override {
                defaultCrateOverrides = pkgs.defaultCrateOverrides // {
                  rosh = attrs: {
                    nativeBuildInputs =
                      with pkgs;
                      [
                        cargo-nextest
                      ]
                      ++ (if stdenv.isLinux then [ pkg-config ] else [ ]);
                    buildInputs = platformDeps;
                    RUST_BACKTRACE = 1;
                    PKG_CONFIG_PATH = pkgs.lib.optionalString pkgs.stdenv.isLinux "${pkgs.openssl.dev}/lib/pkgconfig";
                  };
                };
              };
          };
        in
        {
          packages = {
            default = cargoNix.workspaceMembers.rosh.build;

            # For generating Cargo.nix
            generate-cargo-nix = pkgs.writeShellScriptBin "generate-cargo-nix" ''
              ${crate2nix.packages.${system}.default}/bin/crate2nix generate
            '';
          };

          checks = import ./tests.nix {
            inherit
              pkgs
              toolchain
              platformDeps
              system
              ;
          };

          devShells.default = pkgs.mkShell {
            buildInputs =
              with pkgs;
              [
                # Rust toolchain from Fenix
                toolchain

                # Common development tools
                cargo-nextest
                cargo-watch
                clippy
                cargo-machete
                rust-analyzer
                crate2nix.packages.${system}.default

                # Python and pre-commit
                python313
                pre-commit

                # Platform-specific dependencies
              ]
              ++ platformDeps;

            # Environment variables
            RUST_BACKTRACE = 1;

            # Set up pkg-config paths on Linux
            PKG_CONFIG_PATH = pkgs.lib.optionalString pkgs.stdenv.isLinux "${pkgs.openssl.dev}/lib/pkgconfig";

            # macOS-specific environment
            CARGO_BUILD_TARGET = pkgs.lib.optionalString pkgs.stdenv.isDarwin "aarch64-apple-darwin";

            shellHook = ''
              echo "Rosh development environment"
              echo "Rust toolchain: $(rustc --version)"
              echo "Platform: ${system}"
            '';
          };
        }
      );
    in
    systemOutputs
    // {
      githubActions = nix-github-actions.lib.mkGithubMatrix {
        inherit (systemOutputs) checks;
      };
    };
  nixConfig = {
    extra-substituters = ["https://rosh.cachix.org"];
    extra-trusted-public-keys = ["rosh.cachix.org-1:A7NamsOzYecMVgXDN9seJAmQ/+aOWgKo52PD55HkRr4="];
  };
}
