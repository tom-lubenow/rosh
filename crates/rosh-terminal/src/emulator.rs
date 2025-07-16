//! Terminal emulator core implementation
//!
//! Manages terminal state and processes escape sequences

use crate::{
    framebuffer::{Cell, FrameBuffer},
    parser::Parser,
    TerminalError,
};

/// Terminal emulator
pub struct Terminal {
    /// The parser for escape sequences
    parser: Parser,

    /// Frame buffer containing screen content
    framebuffer: FrameBuffer,

    /// Terminal title
    title: String,

    /// Alternate screen buffer (for full-screen apps)
    alternate_buffer: Option<FrameBuffer>,

    /// Whether we're using the alternate buffer
    use_alternate: bool,

    /// Saved cursor position for primary screen
    saved_cursor: Option<(u16, u16)>,

    /// Saved cursor position for alternate screen
    _saved_cursor_alt: Option<(u16, u16)>,
}

impl Terminal {
    /// Create a new terminal with given dimensions
    pub fn new(width: u16, height: u16) -> Self {
        Self {
            parser: Parser::new(),
            framebuffer: FrameBuffer::new(width, height),
            title: String::new(),
            alternate_buffer: None,
            use_alternate: false,
            saved_cursor: None,
            _saved_cursor_alt: None,
        }
    }

    /// Process input bytes
    pub fn process(&mut self, data: &[u8]) {
        for byte in data {
            self.parser.advance(&mut self.framebuffer, *byte);
        }
    }

    /// Resize the terminal
    pub fn resize(&mut self, width: u16, height: u16) -> Result<(), TerminalError> {
        if width == 0 || height == 0 {
            return Err(TerminalError::SizeError(
                "Invalid terminal size".to_string(),
            ));
        }

        self.framebuffer.resize(width, height);
        if let Some(ref mut alt) = self.alternate_buffer {
            alt.resize(width, height);
        }

        Ok(())
    }

    /// Get current frame buffer
    pub fn framebuffer(&self) -> &FrameBuffer {
        if self.use_alternate {
            self.alternate_buffer.as_ref().unwrap_or(&self.framebuffer)
        } else {
            &self.framebuffer
        }
    }

    /// Get mutable frame buffer
    pub fn framebuffer_mut(&mut self) -> &mut FrameBuffer {
        if self.use_alternate {
            self.alternate_buffer
                .as_mut()
                .unwrap_or(&mut self.framebuffer)
        } else {
            &mut self.framebuffer
        }
    }

    /// Get terminal title
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Set terminal title
    pub fn set_title(&mut self, title: String) {
        self.title = title;
    }

    /// Switch to alternate screen buffer
    pub fn enter_alternate_screen(&mut self) {
        if !self.use_alternate {
            let mut alt = self.framebuffer.clone();
            alt.clear();
            self.alternate_buffer = Some(alt);
            self.use_alternate = true;

            // Save cursor position
            let (x, y) = self.framebuffer.cursor_position();
            self.saved_cursor = Some((x, y));
        }
    }

    /// Switch back to primary screen buffer
    pub fn exit_alternate_screen(&mut self) {
        if self.use_alternate {
            self.use_alternate = false;

            // Restore cursor position
            if let Some((x, y)) = self.saved_cursor.take() {
                self.framebuffer.set_cursor_position(x, y);
            }
        }
    }

    /// Get terminal dimensions
    pub fn dimensions(&self) -> (u16, u16) {
        (self.framebuffer.width(), self.framebuffer.height())
    }

    /// Create a snapshot of current terminal state
    pub fn snapshot(&self) -> TerminalSnapshot {
        TerminalSnapshot {
            width: self.framebuffer.width(),
            height: self.framebuffer.height(),
            cells: self.framebuffer.cells().to_vec(),
            cursor_x: self.framebuffer.cursor_position().0,
            cursor_y: self.framebuffer.cursor_position().1,
            cursor_visible: self.framebuffer.cursor_visible(),
            title: self.title.clone(),
            use_alternate: self.use_alternate,
        }
    }

    /// Restore terminal state from a snapshot
    pub fn restore(&mut self, snapshot: &TerminalSnapshot) -> Result<(), TerminalError> {
        // Resize if needed
        if snapshot.width != self.framebuffer.width()
            || snapshot.height != self.framebuffer.height()
        {
            self.resize(snapshot.width, snapshot.height)?;
        }

        // Restore cells
        self.framebuffer.restore_cells(&snapshot.cells);

        // Restore cursor
        self.framebuffer
            .set_cursor_position(snapshot.cursor_x, snapshot.cursor_y);
        self.framebuffer.set_cursor_visible(snapshot.cursor_visible);

        // Restore title
        self.title = snapshot.title.clone();

        // Handle alternate screen
        if snapshot.use_alternate && !self.use_alternate {
            self.enter_alternate_screen();
        } else if !snapshot.use_alternate && self.use_alternate {
            self.exit_alternate_screen();
        }

        Ok(())
    }
}

/// Snapshot of terminal state
#[derive(Debug, Clone)]
pub struct TerminalSnapshot {
    pub width: u16,
    pub height: u16,
    pub cells: Vec<Cell>,
    pub cursor_x: u16,
    pub cursor_y: u16,
    pub cursor_visible: bool,
    pub title: String,
    pub use_alternate: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_creation() {
        let term = Terminal::new(80, 24);
        assert_eq!(term.dimensions(), (80, 24));
        assert_eq!(term.title(), "");
    }

    #[test]
    fn test_terminal_resize() {
        let mut term = Terminal::new(80, 24);
        term.resize(100, 30).unwrap();
        assert_eq!(term.dimensions(), (100, 30));
    }

    #[test]
    fn test_alternate_screen() {
        let mut term = Terminal::new(80, 24);

        // Write something to primary buffer
        term.framebuffer_mut().write_char('A');
        let (x, y) = term.framebuffer().cursor_position();

        // Switch to alternate
        term.enter_alternate_screen();

        // Alternate should be clear
        let alt_cell = term.framebuffer().cell_at(0, 0).unwrap();
        assert_eq!(alt_cell.c, ' ');

        // Switch back
        term.exit_alternate_screen();

        // Should restore cursor and content
        let (rx, ry) = term.framebuffer().cursor_position();
        assert_eq!((rx, ry), (x, y));

        let cell = term.framebuffer().cell_at(0, 0).unwrap();
        assert_eq!(cell.c, 'A');
    }

    #[test]
    fn test_snapshot_restore() {
        let mut term = Terminal::new(80, 24);

        // Set up some state
        term.set_title("Test Terminal".to_string());
        term.framebuffer_mut().write_char('H');
        term.framebuffer_mut().write_char('i');

        // Take snapshot
        let snapshot = term.snapshot();

        // Modify terminal
        term.framebuffer_mut().clear();
        term.set_title("Modified".to_string());

        // Restore
        term.restore(&snapshot).unwrap();

        // Check restoration
        assert_eq!(term.title(), "Test Terminal");
        let cell = term.framebuffer().cell_at(0, 0).unwrap();
        assert_eq!(cell.c, 'H');
    }
}
