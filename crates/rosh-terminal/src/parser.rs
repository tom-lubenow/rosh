//! Terminal escape sequence parser
//!
//! Uses the vte crate to parse VT100/xterm escape sequences

use crate::framebuffer::{Color, FrameBuffer};
use vte::{Params, Perform};

/// Parser for terminal escape sequences
pub struct Parser {
    /// The underlying vte parser
    vte_parser: vte::Parser,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    /// Create a new parser
    pub fn new() -> Self {
        Self {
            vte_parser: vte::Parser::new(),
        }
    }

    /// Process a single byte
    pub fn advance(&mut self, framebuffer: &mut FrameBuffer, byte: u8) {
        self.vte_parser.advance(framebuffer, byte);
    }
}

/// VTE Perform trait implementation for FrameBuffer
impl Perform for FrameBuffer {
    fn print(&mut self, c: char) {
        self.write_char(c);
    }

    fn execute(&mut self, byte: u8) {
        match byte {
            // Backspace
            0x08 => {
                let (x, y) = self.cursor_position();
                if x > 0 {
                    self.set_cursor_position(x - 1, y);
                }
            }

            // Tab
            0x09 => {
                let (x, y) = self.cursor_position();
                let new_x = ((x / 8) + 1) * 8;
                self.set_cursor_position(new_x.min(self.width() - 1), y);
            }

            // Line feed (newline)
            0x0A => self.newline(),

            // Carriage return
            0x0D => self.carriage_return(),

            // Escape
            0x1B => {} // Handled by CSI/OSC

            _ => {}
        }
    }

    fn hook(&mut self, _params: &Params, _intermediates: &[u8], _ignore: bool, _c: char) {}

    fn put(&mut self, _byte: u8) {}

    fn unhook(&mut self) {}

    fn osc_dispatch(&mut self, params: &[&[u8]], _bell_terminated: bool) {
        if params.is_empty() {
            return;
        }

        // Get the OSC command number
        let command = params[0];
        if command.is_empty() {
            return;
        }

        match command[0] {
            // Set window title
            b'0' | b'2' => {
                if params.len() > 1 {
                    if let Ok(_title) = std::str::from_utf8(params[1]) {
                        // Note: We need to handle title separately in Terminal struct
                        // For now, just ignore
                    }
                }
            }
            _ => {}
        }
    }

    fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], _ignore: bool, c: char) {
        match c {
            // Cursor movement
            'A' => {
                // Cursor up
                let (x, y) = self.cursor_position();
                let n = params.iter().next().map(|p| p[0]).unwrap_or(1).max(1);
                self.set_cursor_position(x, y.saturating_sub(n));
            }

            'B' => {
                // Cursor down
                let (x, y) = self.cursor_position();
                let n = params.iter().next().map(|p| p[0]).unwrap_or(1).max(1);
                self.set_cursor_position(x, (y + n).min(self.height() - 1));
            }

            'C' => {
                // Cursor forward
                let (x, y) = self.cursor_position();
                let n = params.iter().next().map(|p| p[0]).unwrap_or(1).max(1);
                self.set_cursor_position((x + n).min(self.width() - 1), y);
            }

            'D' => {
                // Cursor backward
                let (x, y) = self.cursor_position();
                let n = params.iter().next().map(|p| p[0]).unwrap_or(1).max(1);
                self.set_cursor_position(x.saturating_sub(n), y);
            }

            'H' | 'f' => {
                // Cursor position
                let mut params_iter = params.iter();
                let y = params_iter
                    .next()
                    .and_then(|p| p.first().copied())
                    .unwrap_or(1)
                    .saturating_sub(1);
                let x = params_iter
                    .next()
                    .and_then(|p| p.first().copied())
                    .unwrap_or(1)
                    .saturating_sub(1);
                self.set_cursor_position(x, y);
            }

            // Erase
            'J' => {
                // Erase display
                let mode = params.iter().next().map(|p| p[0]).unwrap_or(0);
                match mode {
                    0 => self.clear_to_end(),
                    1 => self.clear_to_cursor(),
                    2 => self.clear(),
                    _ => {}
                }
            }

            'K' => {
                // Erase line
                let mode = params.iter().next().map(|p| p[0]).unwrap_or(0);
                match mode {
                    0 => self.clear_to_eol(),
                    1 => self.clear_line_to_cursor(),
                    2 => self.clear_line(),
                    _ => {}
                }
            }

            // SGR (Select Graphic Rendition)
            'm' => {
                if params.is_empty() {
                    self.reset_attrs();
                } else {
                    let mut iter = params.iter();
                    while let Some(param) = iter.next() {
                        if let Some(&code) = param.first() {
                            handle_sgr(self, code, &mut iter);
                        }
                    }
                }
            }

            // Cursor visibility
            'h' => {
                if intermediates == b"?" {
                    for param in params.iter() {
                        if let Some(&25) = param.first() {
                            self.set_cursor_visible(true);
                        }
                    }
                }
            }

            'l' => {
                if intermediates == b"?" {
                    for param in params.iter() {
                        if let Some(&25) = param.first() {
                            self.set_cursor_visible(false);
                        }
                    }
                }
            }

            _ => {}
        }
    }

    fn esc_dispatch(&mut self, _intermediates: &[u8], _ignore: bool, _byte: u8) {}
}

/// Handle SGR (Select Graphic Rendition) codes
fn handle_sgr<'a, I>(fb: &mut FrameBuffer, code: u16, params: &mut I)
where
    I: Iterator<Item = &'a [u16]>,
{
    match code {
        0 => fb.reset_attrs(),

        // Attributes
        1 => {
            let mut attrs = fb.current_attrs();
            attrs.bold = true;
            fb.set_attrs(attrs);
        }
        2 => {
            let mut attrs = fb.current_attrs();
            attrs.dim = true;
            fb.set_attrs(attrs);
        }
        3 => {
            let mut attrs = fb.current_attrs();
            attrs.italic = true;
            fb.set_attrs(attrs);
        }
        4 => {
            let mut attrs = fb.current_attrs();
            attrs.underline = true;
            fb.set_attrs(attrs);
        }
        5 => {
            let mut attrs = fb.current_attrs();
            attrs.blink = true;
            fb.set_attrs(attrs);
        }
        7 => {
            let mut attrs = fb.current_attrs();
            attrs.reverse = true;
            fb.set_attrs(attrs);
        }
        8 => {
            let mut attrs = fb.current_attrs();
            attrs.hidden = true;
            fb.set_attrs(attrs);
        }
        9 => {
            let mut attrs = fb.current_attrs();
            attrs.strikethrough = true;
            fb.set_attrs(attrs);
        }

        // Reset attributes
        22 => {
            let mut attrs = fb.current_attrs();
            attrs.bold = false;
            attrs.dim = false;
            fb.set_attrs(attrs);
        }
        23 => {
            let mut attrs = fb.current_attrs();
            attrs.italic = false;
            fb.set_attrs(attrs);
        }
        24 => {
            let mut attrs = fb.current_attrs();
            attrs.underline = false;
            fb.set_attrs(attrs);
        }
        25 => {
            let mut attrs = fb.current_attrs();
            attrs.blink = false;
            fb.set_attrs(attrs);
        }
        27 => {
            let mut attrs = fb.current_attrs();
            attrs.reverse = false;
            fb.set_attrs(attrs);
        }
        28 => {
            let mut attrs = fb.current_attrs();
            attrs.hidden = false;
            fb.set_attrs(attrs);
        }
        29 => {
            let mut attrs = fb.current_attrs();
            attrs.strikethrough = false;
            fb.set_attrs(attrs);
        }

        // Foreground colors
        30..=37 => fb.set_fg_color(Color::Indexed((code - 30) as u8)),
        38 => {
            if let Some(subparam) = params.next() {
                match subparam.first() {
                    Some(&5) => {
                        // 256-color
                        if let Some(color_param) = params.next() {
                            if let Some(&color) = color_param.first() {
                                fb.set_fg_color(Color::Indexed(color as u8));
                            }
                        }
                    }
                    Some(&2) => {
                        // RGB color
                        let r = params.next().and_then(|p| p.first()).copied().unwrap_or(0) as u8;
                        let g = params.next().and_then(|p| p.first()).copied().unwrap_or(0) as u8;
                        let b = params.next().and_then(|p| p.first()).copied().unwrap_or(0) as u8;
                        fb.set_fg_color(Color::Rgb(r, g, b));
                    }
                    _ => {}
                }
            }
        }
        39 => fb.set_fg_color(Color::Default),

        // Background colors
        40..=47 => fb.set_bg_color(Color::Indexed((code - 40) as u8)),
        48 => {
            if let Some(subparam) = params.next() {
                match subparam.first() {
                    Some(&5) => {
                        // 256-color
                        if let Some(color_param) = params.next() {
                            if let Some(&color) = color_param.first() {
                                fb.set_bg_color(Color::Indexed(color as u8));
                            }
                        }
                    }
                    Some(&2) => {
                        // RGB color
                        let r = params.next().and_then(|p| p.first()).copied().unwrap_or(0) as u8;
                        let g = params.next().and_then(|p| p.first()).copied().unwrap_or(0) as u8;
                        let b = params.next().and_then(|p| p.first()).copied().unwrap_or(0) as u8;
                        fb.set_bg_color(Color::Rgb(r, g, b));
                    }
                    _ => {}
                }
            }
        }
        49 => fb.set_bg_color(Color::Default),

        // Bright foreground colors
        90..=97 => fb.set_fg_color(Color::Indexed((code - 90 + 8) as u8)),

        // Bright background colors
        100..=107 => fb.set_bg_color(Color::Indexed((code - 100 + 8) as u8)),

        _ => {}
    }
}
