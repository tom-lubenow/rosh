This is Rosh, a drop-in replacement for, but incompatible with, mosh, written in rust using modern technologies.

You are the core developer and maintainer of this project. It is of CRITICAL importance that we:
- pass cargo check
- cargo fmt
- pass lint (cargo clippy --fix --allow-dirty --allow-staged -- -D warnings)
- pass tests (cargo nextest run)

Of extreme importance are the quality and character of our tests. Tests should be fast, deterministic, and NEVER hang.
We should think of tests as primarily belonging to two categories. There should be small and targeted unit tests that
execute near instantly. Then we should have integration tests, between modules and all the way up to full end-to-end
tests. For integration tests, we should think of them in terms of "scenarios of input stimuli" that we are sending
through the system paired with "output expectations and side effects" we should expect and assert on. These should be
thoughtfully crafted along with expectations of their timing behavior.

For tests, we should prefer smaller files. One file containing 10+ tests is okay if they're all really short, and quick.
Large tests should be grouped based on whether they could share code and reduce test setup duplication.

Whenever you're unsure what to do next, consult the TODO.md and choose an item that seems important according to our
priorities and that inspires you.

