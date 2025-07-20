This is Rosh, a drop-in replacement for, but incompatible with, mosh, written in rust using modern technologies.

Of extreme importance are the quality and character of our tests. Tests should be fast, deterministic, and NEVER hang.
We should think of tests as primarily belonging to two categories. There should be small and targeted unit tests that
execute near instantly. Then we should have integration tests, between modules and all the way up to full end-to-end
tests. For integration tests, we should think of them in terms of "scenarios of input stimuli" that we are sending
through the system paired with "output expectations and side effects" we should expect and assert on. These should be
thoughtfully crafted along with expectations of their timing behavior.

For tests, we should prefer smaller files. One file containing 10+ tests is okay if they're all really short, and quick.
Large tests should be grouped based on whether they could share code and reduce test setup duplication.

CRITICAL TEST PERFORMANCE REQUIREMENT: Any test that takes longer than 20 seconds is a FAILURE and must be removed
or rewritten. Slow tests destroy the entire test suite's value because they discourage running tests frequently.
A test suite is only as useful as its slowest test. Tests that take 30-60+ seconds are absolutely unacceptable.
Delete them immediately - they don't get to hold up development. Fast feedback loops are non-negotiable.

Tests should almost never use hardcoded sleeps, preferring to be event driven. In general, our tests should be considered
first class citizens of this application. They should be high quality, designed as you would normal code. They should be
refactored periodically to promote good architecture and code reuse. Prefer not to keep in disabled or nonfunctional tests,
they're just noise.

For manual interation, you use the following workflow on the nixos vm we have running, called "builder"
::: nix build .#packages.aarch64-linux.default --print-out-paths; nix build .#packages.aarch64-darwin.default --print-out-paths
  warning: Git tree '/Users/tomlubenow/proj/rosh' is dirty
  /nix/store/6qm259q55zviw663jkhvlvscr3nhbwk3-rust_rosh-0.1.0
  warning: Git tree '/Users/tomlubenow/proj/rosh' is dirty
  /nix/store/cfbdq9kkx5rhxfnxpf09m1iz6qswbh3v-rust_rosh-0.1.0
::: result/bin/rosh -d --rosh-server-bin /nix/store/6qm259q55zviw663jkhvlvscr3nhbwk3-rust_rosh-0.1.0/bin/rosh-server builder 'echo $ROSH'
This works because the builder is a nix linux-builder and so the store paths will be the same on our machine and the vm.

Keep commits as you make progress. Our pre-commit script will ensure only code meeting high quality standards can be
committed.
