use rosh_terminal::Terminal;

#[test]
fn cursor_position_and_erase_line_to_eol() {
    let mut term = Terminal::new(5, 2);

    // Write three chars on row 0
    term.process(b"abc");
    // Move cursor to row 1, col 2 (1-based in CSI), i.e., (x=1, y=0)
    term.process(b"\x1b[1;2H");
    // Erase to end of line
    term.process(b"\x1b[K");

    let fb = term.framebuffer();
    let row0: String = (0..fb.width())
        .filter_map(|x| fb.cell_at(x, 0).map(|c| c.c))
        .collect();

    // Expect: 'a' remains, positions 1.. end cleared to spaces
    assert_eq!(row0.chars().next().unwrap(), 'a');
    assert!(row0[1..].chars().all(|c| c == ' '));
}
