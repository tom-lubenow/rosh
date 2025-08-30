use rosh_state::diff::StateDiff;
use rosh_terminal::{framebuffer_to_state, Terminal};

#[test]
fn terminal_to_state_then_diff_and_apply() {
    let mut term = Terminal::new(5, 2);
    term.process(b"abc");

    let state_a = framebuffer_to_state(term.framebuffer(), term.title());
    let mut state_b = state_a.clone();
    // Change one character: 'b' -> 'x'
    let idx = 1usize;
    state_b.screen[idx] = b'x';

    let diff = StateDiff::generate(&state_a, &state_b).expect("generate");
    let reconstructed = diff.apply(&state_a).expect("apply");
    assert_eq!(reconstructed, state_b);
}
