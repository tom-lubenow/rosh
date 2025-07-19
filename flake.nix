{
  description = "Rosh development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, fenix, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        
        # Get the Fenix toolchain
        toolchain = fenix.packages.${system}.stable.toolchain;
        
        # Platform-specific dependencies
        platformDeps = with pkgs; 
          if stdenv.isDarwin then [
            libiconv
          ] else [
            # Linux-specific dependencies
            openssl
            pkg-config
          ];
      in
      {
        packages = {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "rosh";
            version = "0.1.0";
            
            src = ./.;
            
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            
            nativeBuildInputs = with pkgs; [ toolchain cargo-nextest ] ++ 
              (if stdenv.isLinux then [ pkg-config ] else []);
            
            buildInputs = platformDeps;
            
            # Use cargo nextest for testing
            checkPhase = ''
              runHook preCheck
              cargo nextest run --release
              runHook postCheck
            '';
            
            # Environment setup
            RUST_BACKTRACE = 1;
            PKG_CONFIG_PATH = pkgs.lib.optionalString pkgs.stdenv.isLinux
              "${pkgs.openssl.dev}/lib/pkgconfig";
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust toolchain from Fenix
            toolchain
            
            # Common development tools
            cargo-nextest
            cargo-watch
            rust-analyzer
            
            # Platform-specific dependencies
          ] ++ platformDeps;

          # Environment variables
          RUST_BACKTRACE = 1;
          
          # Set up pkg-config paths on Linux
          PKG_CONFIG_PATH = pkgs.lib.optionalString pkgs.stdenv.isLinux
            "${pkgs.openssl.dev}/lib/pkgconfig";
            
          # macOS-specific environment
          CARGO_BUILD_TARGET = pkgs.lib.optionalString pkgs.stdenv.isDarwin
            "aarch64-apple-darwin";
            
          shellHook = ''
            echo "Rosh development environment"
            echo "Rust toolchain: $(rustc --version)"
            echo "Platform: ${system}"
          '';
        };
      });
}
