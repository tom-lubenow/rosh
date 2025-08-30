use rosh_state::diff::StateDiff;
use rosh_terminal::TerminalState;

#[test]
fn state_diff_apply_reconstructs_new_state() {
    // Build a small initial state
    let mut old = TerminalState::new(8, 3);
    old.cursor_x = 1;
    old.cursor_y = 1;
    old.cursor_visible = true;
    old.title = "old".to_string();
    old.scrollback.push(b"oldline".to_vec());
    old.screen[0] = b'A';
    old.attributes[0] = 0x01; // bold

    // Create a modified state
    let mut new = old.clone();
    new.cursor_x = 2;
    new.cursor_y = 2;
    new.title = "new".to_string();
    new.scrollback.push(b"second".to_vec());
    new.screen[0] = b'B';
    new.attributes[0] = 0x02; // italic

    // Generate diff and apply
    let diff = StateDiff::generate(&old, &new).expect("generate");
    let reconstructed = diff.apply(&old).expect("apply");

    assert_eq!(reconstructed, new);
}
