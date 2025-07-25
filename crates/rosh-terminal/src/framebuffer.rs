//! Frame buffer implementation for terminal content
//!
//! Manages the 2D grid of cells that make up the terminal display

use rkyv::{Archive, Deserialize, Serialize};

/// A single cell in the terminal
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Copy, PartialEq)]
#[archive(check_bytes)]
pub struct Cell {
    /// The character in this cell
    pub c: char,

    /// Foreground color (ANSI 256-color palette or RGB)
    pub fg: Color,

    /// Background color
    pub bg: Color,

    /// Text attributes
    pub attrs: Attributes,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            c: ' ',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        }
    }
}

/// Color representation
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Copy, PartialEq)]
#[archive(check_bytes)]
pub enum Color {
    /// Default terminal color
    Default,

    /// ANSI 256-color palette index
    Indexed(u8),

    /// RGB color
    Rgb(u8, u8, u8),
}

/// Text attributes
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Copy, PartialEq)]
#[archive(check_bytes)]
#[derive(Default)]
pub struct Attributes {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikethrough: bool,
    pub reverse: bool,
    pub hidden: bool,
    pub dim: bool,
    pub blink: bool,
}

/// Frame buffer containing terminal content
#[derive(Debug, Clone)]
pub struct FrameBuffer {
    /// Width of the terminal
    width: u16,

    /// Height of the terminal
    height: u16,

    /// Cells in row-major order
    cells: Vec<Cell>,

    /// Cursor X position (0-based)
    cursor_x: u16,

    /// Cursor Y position (0-based)
    cursor_y: u16,

    /// Whether cursor is visible
    cursor_visible: bool,

    /// Current text attributes for new characters
    current_attrs: Attributes,

    /// Current foreground color
    current_fg: Color,

    /// Current background color
    current_bg: Color,

    /// Scrollback buffer
    scrollback: Vec<Vec<Cell>>,

    /// Maximum scrollback lines
    max_scrollback: usize,
}

impl FrameBuffer {
    /// Create a new frame buffer
    pub fn new(width: u16, height: u16) -> Self {
        let cells = vec![Cell::default(); (width as usize) * (height as usize)];

        Self {
            width,
            height,
            cells,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: true,
            current_attrs: Attributes::default(),
            current_fg: Color::Default,
            current_bg: Color::Default,
            scrollback: Vec::new(),
            max_scrollback: 10000,
        }
    }

    /// Get terminal width
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Get terminal height
    pub fn height(&self) -> u16 {
        self.height
    }

    /// Get cursor position
    pub fn cursor_position(&self) -> (u16, u16) {
        (self.cursor_x, self.cursor_y)
    }

    /// Set cursor position
    pub fn set_cursor_position(&mut self, x: u16, y: u16) {
        self.cursor_x = x.min(self.width - 1);
        self.cursor_y = y.min(self.height - 1);
    }

    /// Get cursor visibility
    pub fn cursor_visible(&self) -> bool {
        self.cursor_visible
    }

    /// Set cursor visibility
    pub fn set_cursor_visible(&mut self, visible: bool) {
        self.cursor_visible = visible;
    }

    /// Get cell at position
    pub fn cell_at(&self, x: u16, y: u16) -> Option<&Cell> {
        if x >= self.width || y >= self.height {
            return None;
        }

        let index = (y as usize) * (self.width as usize) + (x as usize);
        self.cells.get(index)
    }

    /// Get mutable cell at position
    pub fn cell_at_mut(&mut self, x: u16, y: u16) -> Option<&mut Cell> {
        if x >= self.width || y >= self.height {
            return None;
        }

        let index = (y as usize) * (self.width as usize) + (x as usize);
        self.cells.get_mut(index)
    }

    /// Write a character at current cursor position
    pub fn write_char(&mut self, c: char) {
        // Store current attributes before borrowing
        let fg = self.current_fg;
        let bg = self.current_bg;
        let attrs = self.current_attrs;

        if let Some(cell) = self.cell_at_mut(self.cursor_x, self.cursor_y) {
            cell.c = c;
            cell.fg = fg;
            cell.bg = bg;
            cell.attrs = attrs;
        }

        // Advance cursor
        self.cursor_x += 1;
        if self.cursor_x >= self.width {
            self.cursor_x = 0;
            self.cursor_y += 1;
            if self.cursor_y >= self.height {
                self.scroll_up(1);
                self.cursor_y = self.height - 1;
            }
        }
    }

    /// Move cursor to next line
    pub fn newline(&mut self) {
        self.cursor_x = 0;
        self.cursor_y += 1;
        if self.cursor_y >= self.height {
            self.scroll_up(1);
            self.cursor_y = self.height - 1;
        }
    }

    /// Carriage return (move to start of line)
    pub fn carriage_return(&mut self) {
        self.cursor_x = 0;
    }

    /// Clear the screen
    pub fn clear(&mut self) {
        self.cells.fill(Cell::default());
        self.cursor_x = 0;
        self.cursor_y = 0;
    }

    /// Clear from cursor to end of screen
    pub fn clear_to_end(&mut self) {
        let start = (self.cursor_y as usize) * (self.width as usize) + (self.cursor_x as usize);
        for cell in &mut self.cells[start..] {
            *cell = Cell::default();
        }
    }

    /// Clear from cursor to end of line
    pub fn clear_to_eol(&mut self) {
        let start = self.cursor_x as usize;
        let end = self.width as usize;
        let row_start = (self.cursor_y as usize) * (self.width as usize);

        for x in start..end {
            self.cells[row_start + x] = Cell::default();
        }
    }

    /// Clear from beginning of screen to cursor (inclusive)
    pub fn clear_to_cursor(&mut self) {
        let cursor_pos =
            (self.cursor_y as usize) * (self.width as usize) + (self.cursor_x as usize);
        for i in 0..=cursor_pos {
            if i < self.cells.len() {
                self.cells[i] = Cell::default();
            }
        }
    }

    /// Clear from beginning of line to cursor (inclusive)
    pub fn clear_line_to_cursor(&mut self) {
        let row_start = (self.cursor_y as usize) * (self.width as usize);
        let cursor_pos = row_start + (self.cursor_x as usize);

        for i in row_start..=cursor_pos {
            if i < self.cells.len() {
                self.cells[i] = Cell::default();
            }
        }
    }

    /// Clear entire line
    pub fn clear_line(&mut self) {
        let row_start = (self.cursor_y as usize) * (self.width as usize);
        let row_end = row_start + (self.width as usize);

        for i in row_start..row_end {
            if i < self.cells.len() {
                self.cells[i] = Cell::default();
            }
        }
    }

    /// Scroll screen up by n lines
    pub fn scroll_up(&mut self, n: u16) {
        if n == 0 || n > self.height {
            return;
        }

        // Save scrolled lines to scrollback
        for i in 0..n {
            let row_start = (i as usize) * (self.width as usize);
            let row_end = row_start + (self.width as usize);
            let row = self.cells[row_start..row_end].to_vec();
            self.scrollback.push(row);

            // Limit scrollback size
            if self.scrollback.len() > self.max_scrollback {
                self.scrollback.remove(0);
            }
        }

        // Shift cells up
        let shift = (n as usize) * (self.width as usize);
        self.cells.rotate_left(shift);

        // Clear new lines at bottom
        let clear_start = ((self.height - n) as usize) * (self.width as usize);
        for cell in &mut self.cells[clear_start..] {
            *cell = Cell::default();
        }
    }

    /// Get current text attributes
    pub fn current_attrs(&self) -> Attributes {
        self.current_attrs
    }

    /// Set current text attributes
    pub fn set_attrs(&mut self, attrs: Attributes) {
        self.current_attrs = attrs;
    }

    /// Set current foreground color
    pub fn set_fg_color(&mut self, color: Color) {
        self.current_fg = color;
    }

    /// Set current background color
    pub fn set_bg_color(&mut self, color: Color) {
        self.current_bg = color;
    }

    /// Reset text attributes and colors
    pub fn reset_attrs(&mut self) {
        self.current_attrs = Attributes::default();
        self.current_fg = Color::Default;
        self.current_bg = Color::Default;
    }

    /// Resize the frame buffer
    pub fn resize(&mut self, new_width: u16, new_height: u16) {
        let old_width = self.width;
        let old_height = self.height;

        // Create new buffer
        let mut new_cells = vec![Cell::default(); (new_width as usize) * (new_height as usize)];

        // Copy existing content
        let copy_width = old_width.min(new_width) as usize;
        let copy_height = old_height.min(new_height) as usize;

        for y in 0..copy_height {
            let old_start = y * (old_width as usize);
            let new_start = y * (new_width as usize);

            new_cells[new_start..new_start + copy_width]
                .copy_from_slice(&self.cells[old_start..old_start + copy_width]);
        }

        self.cells = new_cells;
        self.width = new_width;
        self.height = new_height;

        // Adjust cursor position
        self.cursor_x = self.cursor_x.min(new_width - 1);
        self.cursor_y = self.cursor_y.min(new_height - 1);
    }

    /// Get all cells (for serialization)
    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }

    /// Restore cells from a slice
    pub fn restore_cells(&mut self, cells: &[Cell]) {
        if cells.len() == self.cells.len() {
            self.cells.copy_from_slice(cells);
        }
    }

    /// Get scrollback buffer
    pub fn scrollback(&self) -> &[Vec<Cell>] {
        &self.scrollback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framebuffer_creation() {
        let fb = FrameBuffer::new(80, 24);
        assert_eq!(fb.width(), 80);
        assert_eq!(fb.height(), 24);
        assert_eq!(fb.cursor_position(), (0, 0));
    }

    #[test]
    fn test_write_char() {
        let mut fb = FrameBuffer::new(80, 24);

        fb.write_char('H');
        fb.write_char('i');

        assert_eq!(fb.cell_at(0, 0).unwrap().c, 'H');
        assert_eq!(fb.cell_at(1, 0).unwrap().c, 'i');
        assert_eq!(fb.cursor_position(), (2, 0));
    }

    #[test]
    fn test_newline() {
        let mut fb = FrameBuffer::new(80, 24);

        fb.write_char('A');
        fb.newline();
        fb.write_char('B');

        assert_eq!(fb.cell_at(0, 0).unwrap().c, 'A');
        assert_eq!(fb.cell_at(0, 1).unwrap().c, 'B');
        assert_eq!(fb.cursor_position(), (1, 1));
    }

    #[test]
    fn test_wrap_around() {
        let mut fb = FrameBuffer::new(3, 2);

        // Fill first line
        fb.write_char('A');
        fb.write_char('B');
        fb.write_char('C');

        // Should wrap to next line
        fb.write_char('D');

        assert_eq!(fb.cell_at(0, 1).unwrap().c, 'D');
        assert_eq!(fb.cursor_position(), (1, 1));
    }

    #[test]
    fn test_scroll() {
        let mut fb = FrameBuffer::new(3, 2);

        // Fill both lines
        fb.write_char('A');
        fb.write_char('B');
        fb.write_char('C');
        fb.write_char('D');
        fb.write_char('E');
        fb.write_char('F');

        // Next write should cause scroll
        fb.write_char('G');

        // First line should now have DEF
        assert_eq!(fb.cell_at(0, 0).unwrap().c, 'D');
        assert_eq!(fb.cell_at(1, 0).unwrap().c, 'E');
        assert_eq!(fb.cell_at(2, 0).unwrap().c, 'F');

        // Second line should have G
        assert_eq!(fb.cell_at(0, 1).unwrap().c, 'G');

        // Check scrollback
        assert_eq!(fb.scrollback.len(), 1);
        assert_eq!(fb.scrollback[0][0].c, 'A');
        assert_eq!(fb.scrollback[0][1].c, 'B');
        assert_eq!(fb.scrollback[0][2].c, 'C');
    }

    #[test]
    fn test_clear() {
        let mut fb = FrameBuffer::new(80, 24);

        fb.write_char('X');
        fb.clear();

        assert_eq!(fb.cell_at(0, 0).unwrap().c, ' ');
        assert_eq!(fb.cursor_position(), (0, 0));
    }

    #[test]
    fn test_resize() {
        let mut fb = FrameBuffer::new(5, 3);

        // Write some content
        fb.write_char('A');
        fb.write_char('B');
        fb.newline();
        fb.write_char('C');

        // Resize smaller
        fb.resize(3, 2);

        // Content should be preserved
        assert_eq!(fb.cell_at(0, 0).unwrap().c, 'A');
        assert_eq!(fb.cell_at(1, 0).unwrap().c, 'B');
        assert_eq!(fb.cell_at(0, 1).unwrap().c, 'C');

        // Resize larger
        fb.resize(10, 5);

        // Content should still be preserved
        assert_eq!(fb.cell_at(0, 0).unwrap().c, 'A');
        assert_eq!(fb.cell_at(1, 0).unwrap().c, 'B');
        assert_eq!(fb.cell_at(0, 1).unwrap().c, 'C');
    }

    #[test]
    fn test_clear_to_cursor() {
        let mut fb = FrameBuffer::new(4, 3);

        // Fill cells directly without triggering scrolling
        fb.cells[0] = Cell {
            c: 'A',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[1] = Cell {
            c: 'B',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[2] = Cell {
            c: 'C',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[3] = Cell {
            c: 'D',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };

        fb.cells[4] = Cell {
            c: 'E',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[5] = Cell {
            c: 'F',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[6] = Cell {
            c: 'G',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[7] = Cell {
            c: 'H',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };

        fb.cells[8] = Cell {
            c: 'I',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[9] = Cell {
            c: 'J',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[10] = Cell {
            c: 'K',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[11] = Cell {
            c: 'L',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };

        // Position cursor at (2, 1)
        fb.set_cursor_position(2, 1);

        // Clear to cursor
        fb.clear_to_cursor();

        // Everything up to and including cursor position should be cleared
        // First row should be all spaces
        for x in 0..4 {
            assert_eq!(fb.cell_at(x, 0).unwrap().c, ' ');
        }

        // Second row up to cursor should be spaces
        assert_eq!(fb.cell_at(0, 1).unwrap().c, ' ');
        assert_eq!(fb.cell_at(1, 1).unwrap().c, ' ');
        assert_eq!(fb.cell_at(2, 1).unwrap().c, ' ');

        // Rest should be unchanged
        assert_eq!(fb.cell_at(3, 1).unwrap().c, 'H');
        assert_eq!(fb.cell_at(0, 2).unwrap().c, 'I');
    }

    #[test]
    fn test_clear_line_to_cursor() {
        let mut fb = FrameBuffer::new(5, 2);

        // Fill cells directly to avoid wrapping
        fb.cells[0] = Cell {
            c: 'A',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[1] = Cell {
            c: 'B',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[2] = Cell {
            c: 'C',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[3] = Cell {
            c: 'D',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[4] = Cell {
            c: 'E',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };

        fb.cells[5] = Cell {
            c: 'F',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[6] = Cell {
            c: 'G',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[7] = Cell {
            c: 'H',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[8] = Cell {
            c: 'I',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[9] = Cell {
            c: 'J',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };

        // Position cursor at (3, 1)
        fb.set_cursor_position(3, 1);

        // Clear line to cursor
        fb.clear_line_to_cursor();

        // First line should be unchanged
        assert_eq!(fb.cell_at(0, 0).unwrap().c, 'A');
        assert_eq!(fb.cell_at(4, 0).unwrap().c, 'E');

        // Second line up to cursor should be cleared
        assert_eq!(fb.cell_at(0, 1).unwrap().c, ' ');
        assert_eq!(fb.cell_at(1, 1).unwrap().c, ' ');
        assert_eq!(fb.cell_at(2, 1).unwrap().c, ' ');
        assert_eq!(fb.cell_at(3, 1).unwrap().c, ' ');

        // Rest of second line unchanged
        assert_eq!(fb.cell_at(4, 1).unwrap().c, 'J');
    }

    #[test]
    fn test_clear_line() {
        let mut fb = FrameBuffer::new(4, 3);

        // Fill cells directly
        fb.cells[0] = Cell {
            c: 'A',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[1] = Cell {
            c: 'B',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[2] = Cell {
            c: 'C',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[3] = Cell {
            c: 'D',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };

        fb.cells[4] = Cell {
            c: 'E',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[5] = Cell {
            c: 'F',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[6] = Cell {
            c: 'G',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[7] = Cell {
            c: 'H',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };

        fb.cells[8] = Cell {
            c: 'I',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[9] = Cell {
            c: 'J',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[10] = Cell {
            c: 'K',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };
        fb.cells[11] = Cell {
            c: 'L',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
        };

        // Position cursor on second line
        fb.set_cursor_position(2, 1);

        // Clear entire line
        fb.clear_line();

        // First line unchanged
        assert_eq!(fb.cell_at(0, 0).unwrap().c, 'A');
        assert_eq!(fb.cell_at(3, 0).unwrap().c, 'D');

        // Second line cleared
        for x in 0..4 {
            assert_eq!(fb.cell_at(x, 1).unwrap().c, ' ');
        }

        // Third line unchanged
        assert_eq!(fb.cell_at(0, 2).unwrap().c, 'I');
        assert_eq!(fb.cell_at(3, 2).unwrap().c, 'L');
    }
}
