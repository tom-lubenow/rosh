This is Rosh, a drop-in replacement for, but incompatible with, mosh, written in rust using modern technologies.

For manual interation, you use the following workflow on the nixos vm we have running, called "builder"
::: nix build .#packages.aarch64-linux.default --print-out-paths; nix build .#packages.aarch64-darwin.default --print-out-paths
  warning: Git tree '/Users/tomlubenow/proj/rosh' is dirty
  /nix/store/6qm259q55zviw663jkhvlvscr3nhbwk3-rust_rosh-0.1.0
  warning: Git tree '/Users/tomlubenow/proj/rosh' is dirty
  /nix/store/cfbdq9kkx5rhxfnxpf09m1iz6qswbh3v-rust_rosh-0.1.0
::: result/bin/rosh -d --rosh-server-bin /nix/store/6qm259q55zviw663jkhvlvscr3nhbwk3-rust_rosh-0.1.0/bin/rosh-server builder 'echo $ROSH'
This works because the builder is a nix linux-builder and so the store paths will be the same on our machine and the vm.

Keep commits as you make progress. Our pre-commit script will ensure only code meeting high quality standards can be committed.
Consider using cargo fmt and cargo clippy --fix --allow-dirty --allow-staged -- -D warnings along the way to leverage automation.
