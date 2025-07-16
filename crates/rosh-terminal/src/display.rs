//! Terminal display conversion
//! 
//! Converts terminal state to formats suitable for display

use crate::framebuffer::{FrameBuffer, Cell, Color, Attributes};
use crate::state::TerminalState;

/// Convert a FrameBuffer to a TerminalState for synchronization
pub fn framebuffer_to_state(fb: &FrameBuffer, title: &str) -> TerminalState {
    let width = fb.width();
    let height = fb.height();
    let (cursor_x, cursor_y) = fb.cursor_position();
    
    // Flatten cells to screen buffer
    let mut screen = Vec::with_capacity((width * height) as usize);
    let mut attributes = Vec::with_capacity((width * height) as usize);
    
    for y in 0..height {
        for x in 0..width {
            if let Some(cell) = fb.cell_at(x, y) {
                screen.push(cell.c as u8);
                attributes.push(cell_to_attribute(cell));
            } else {
                screen.push(b' ');
                attributes.push(0);
            }
        }
    }
    
    TerminalState {
        width,
        height,
        screen,
        cursor_x,
        cursor_y,
        cursor_visible: fb.cursor_visible(),
        title: title.to_string(),
        scrollback: Vec::new(), // TODO: Convert scrollback
        attributes,
    }
}

/// Convert a TerminalState to a FrameBuffer
pub fn state_to_framebuffer(state: &TerminalState, fb: &mut FrameBuffer) {
    // Resize framebuffer if needed
    if fb.width() != state.width || fb.height() != state.height {
        fb.resize(state.width, state.height);
    }
    
    // Update cells
    for y in 0..state.height {
        for x in 0..state.width {
            let idx = (y * state.width + x) as usize;
            if idx < state.screen.len() {
                let c = state.screen[idx] as char;
                let attr_byte = state.attributes.get(idx).copied().unwrap_or(0);
                let (fg, bg, attrs) = attribute_to_cell_attrs(attr_byte);
                
                if let Some(cell) = fb.cell_at_mut(x, y) {
                    cell.c = c;
                    cell.fg = fg;
                    cell.bg = bg;
                    cell.attrs = attrs;
                }
            }
        }
    }
    
    // Update cursor
    fb.set_cursor_position(state.cursor_x, state.cursor_y);
    fb.set_cursor_visible(state.cursor_visible);
}

/// Convert a TerminalState back to cells for a FrameBuffer
pub fn state_to_cells(state: &TerminalState) -> Vec<Cell> {
    let mut cells = Vec::with_capacity(state.screen.len());
    
    for i in 0..state.screen.len() {
        let c = state.screen[i] as char;
        let attr_byte = state.attributes.get(i).copied().unwrap_or(0);
        let (fg, bg, attrs) = attribute_to_cell_attrs(attr_byte);
        
        cells.push(Cell { c, fg, bg, attrs });
    }
    
    cells
}

/// Convert cell attributes to a compact byte representation
fn cell_to_attribute(cell: &Cell) -> u8 {
    let mut attr = 0u8;
    
    // Pack text attributes into lower 7 bits
    if cell.attrs.bold { attr |= 0x01; }
    if cell.attrs.italic { attr |= 0x02; }
    if cell.attrs.underline { attr |= 0x04; }
    if cell.attrs.strikethrough { attr |= 0x08; }
    if cell.attrs.reverse { attr |= 0x10; }
    if cell.attrs.dim { attr |= 0x20; }
    if cell.attrs.blink { attr |= 0x40; }
    // Bit 7 reserved for future use
    
    // For now, we're only storing basic attributes
    // Colors would need a more complex encoding scheme
    attr
}

/// Convert attribute byte back to cell attributes
fn attribute_to_cell_attrs(attr: u8) -> (Color, Color, Attributes) {
    let attrs = Attributes {
        bold: attr & 0x01 != 0,
        italic: attr & 0x02 != 0,
        underline: attr & 0x04 != 0,
        strikethrough: attr & 0x08 != 0,
        reverse: attr & 0x10 != 0,
        dim: attr & 0x20 != 0,
        blink: attr & 0x40 != 0,
        hidden: false, // Not encoded in compact form
    };
    
    // Default colors for now
    (Color::Default, Color::Default, attrs)
}

/// Render a row of cells to a string with ANSI escape codes
pub fn render_row_ansi(fb: &FrameBuffer, row: u16) -> String {
    let mut output = String::new();
    let mut last_fg = Color::Default;
    let mut last_bg = Color::Default;
    let mut last_attrs = Attributes::default();
    
    for x in 0..fb.width() {
        if let Some(cell) = fb.cell_at(x, row) {
            // Check if we need to update attributes
            if cell.fg != last_fg || cell.bg != last_bg || cell.attrs != last_attrs {
                output.push_str(&cell_to_ansi(cell));
                last_fg = cell.fg;
                last_bg = cell.bg;
                last_attrs = cell.attrs;
            }
            
            output.push(cell.c);
        }
    }
    
    // Reset at end of line
    output.push_str("\x1b[0m");
    output
}

/// Convert cell attributes to ANSI escape sequence
fn cell_to_ansi(cell: &Cell) -> String {
    let mut codes = Vec::new();
    
    // Reset first
    codes.push(0);
    
    // Text attributes
    if cell.attrs.bold { codes.push(1); }
    if cell.attrs.dim { codes.push(2); }
    if cell.attrs.italic { codes.push(3); }
    if cell.attrs.underline { codes.push(4); }
    if cell.attrs.blink { codes.push(5); }
    if cell.attrs.reverse { codes.push(7); }
    if cell.attrs.hidden { codes.push(8); }
    if cell.attrs.strikethrough { codes.push(9); }
    
    // Foreground color
    match cell.fg {
        Color::Default => {}
        Color::Indexed(n) if n < 8 => codes.push(30 + n as u16),
        Color::Indexed(n) if n < 16 => codes.push(90 + (n - 8) as u16),
        Color::Indexed(n) => {
            codes.push(38);
            codes.push(5);
            codes.push(n as u16);
        }
        Color::Rgb(r, g, b) => {
            codes.push(38);
            codes.push(2);
            codes.push(r as u16);
            codes.push(g as u16);
            codes.push(b as u16);
        }
    }
    
    // Background color
    match cell.bg {
        Color::Default => {}
        Color::Indexed(n) if n < 8 => codes.push(40 + n as u16),
        Color::Indexed(n) if n < 16 => codes.push(100 + (n - 8) as u16),
        Color::Indexed(n) => {
            codes.push(48);
            codes.push(5);
            codes.push(n as u16);
        }
        Color::Rgb(r, g, b) => {
            codes.push(48);
            codes.push(2);
            codes.push(r as u16);
            codes.push(g as u16);
            codes.push(b as u16);
        }
    }
    
    // Build escape sequence
    if codes.len() == 1 && codes[0] == 0 {
        "\x1b[0m".to_string()
    } else {
        format!("\x1b[{}m", codes.iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(";"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_framebuffer_to_state() {
        let mut fb = FrameBuffer::new(3, 2);
        fb.write_char('A');
        fb.write_char('B');
        fb.newline();
        fb.write_char('C');
        
        let state = framebuffer_to_state(&fb, "Test");
        
        assert_eq!(state.width, 3);
        assert_eq!(state.height, 2);
        assert_eq!(state.screen[0], b'A');
        assert_eq!(state.screen[1], b'B');
        assert_eq!(state.screen[3], b'C');
        assert_eq!(state.title, "Test");
    }
    
    #[test]
    fn test_state_to_cells() {
        let state = TerminalState {
            width: 2,
            height: 2,
            screen: vec![b'X', b'Y', b'Z', b' '],
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: true,
            title: String::new(),
            scrollback: Vec::new(),
            attributes: vec![0, 0, 0, 0],
        };
        
        let cells = state_to_cells(&state);
        
        assert_eq!(cells.len(), 4);
        assert_eq!(cells[0].c, 'X');
        assert_eq!(cells[1].c, 'Y');
        assert_eq!(cells[2].c, 'Z');
        assert_eq!(cells[3].c, ' ');
    }
    
    #[test]
    fn test_attribute_encoding() {
        let mut attrs = Attributes::default();
        attrs.bold = true;
        attrs.underline = true;
        
        let cell = Cell {
            c: 'A',
            fg: Color::Default,
            bg: Color::Default,
            attrs,
        };
        
        let encoded = cell_to_attribute(&cell);
        assert_eq!(encoded & 0x01, 0x01); // bold
        assert_eq!(encoded & 0x04, 0x04); // underline
        
        let (_, _, decoded_attrs) = attribute_to_cell_attrs(encoded);
        assert!(decoded_attrs.bold);
        assert!(decoded_attrs.underline);
    }
    
    #[test]
    fn test_ansi_rendering() {
        let mut fb = FrameBuffer::new(5, 1);
        
        // Set bold red text
        fb.set_attrs(Attributes { bold: true, ..Default::default() });
        fb.set_fg_color(Color::Indexed(1)); // Red
        fb.write_char('R');
        fb.write_char('E');
        fb.write_char('D');
        
        let rendered = render_row_ansi(&fb, 0);
        
        // Should contain bold (1) and red (31) codes
        assert!(rendered.contains("\x1b["));
        assert!(rendered.contains("RED"));
        assert!(rendered.ends_with("\x1b[0m"));
    }
}