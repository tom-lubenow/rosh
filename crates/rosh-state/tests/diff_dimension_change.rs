use rosh_state::diff::StateDiff;
use rosh_terminal::TerminalState;

#[test]
fn dimension_change_full_resize_and_copy() {
    let mut old = TerminalState::new(4, 2); // 8 cells
                                            // Put distinct content to verify it's replaced after resize
    old.screen.copy_from_slice(b"ABCDEFGH");
    old.attributes.copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

    let mut new = TerminalState::new(5, 3); // 15 cells
    new.title = "resized".to_string();
    new.screen[..5].copy_from_slice(b"hello");
    new.attributes[..5].copy_from_slice(&[9, 9, 9, 9, 9]);

    let diff = StateDiff::generate(&old, &new).expect("generate");
    assert!(
        diff.dimension_change.is_some(),
        "should mark dimension change"
    );

    let applied = diff.apply(&old).expect("apply");
    assert_eq!(applied.width, 5);
    assert_eq!(applied.height, 3);
    assert_eq!(&applied.screen[..5], b"hello");
    assert_eq!(&applied.attributes[..5], &[9, 9, 9, 9, 9]);
}
