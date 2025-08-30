use rosh_terminal::{framebuffer::Color, Terminal};

#[test]
fn parser_applies_sgr_attributes_and_colors() {
    let mut term = Terminal::new(10, 2);

    // Bold + 256-color fg (196 is bright red)
    let seq = b"\x1b[1;38;5;196mB";
    term.process(seq);

    let fb = term.framebuffer();
    let cell = fb.cell_at(0, 0).expect("cell (0,0)");
    assert_eq!(cell.c, 'B');
    assert!(cell.attrs.bold, "bold should be set");
    assert_eq!(cell.fg, Color::Indexed(196));
}
