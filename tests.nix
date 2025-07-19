{
  pkgs,
  toolchain,
  platformDeps,
  system,
}:

# Only include tests on aarch64-darwin for now
if system == "aarch64-darwin" then
  {
    test = pkgs.stdenv.mkDerivation {
      name = "cargo-test";
      src = ./.;
      buildInputs = [
        toolchain
        pkgs.cargo-nextest
      ]
      ++ platformDeps;
      buildPhase = ''
        export HOME=$TMPDIR
        cargo nextest run --no-fail-fast
      '';
      installPhase = ''
        touch $out
      '';
      RUST_BACKTRACE = 1;
    };
  }
else
  {
    # Empty checks for other systems
  }
