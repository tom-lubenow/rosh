//! Error handling tests for rosh-terminal module

use rosh_terminal::{Attributes, Cell, Color, FrameBuffer, Parser, Terminal, TerminalState};

#[test]
fn test_framebuffer_out_of_bounds() {
    let fb = FrameBuffer::new(80, 24);

    // Test out of bounds access
    assert!(fb.cell_at(80, 0).is_none());
    assert!(fb.cell_at(0, 24).is_none());
    assert!(fb.cell_at(100, 100).is_none());

    // Test negative-like coordinates (using large values that would wrap)
    let large_x = u16::MAX;
    let large_y = u16::MAX;
    assert!(fb.cell_at(large_x, large_y).is_none());
}

#[test]
fn test_framebuffer_zero_dimensions() {
    // Test creating framebuffer with zero dimensions
    let fb = FrameBuffer::new(0, 0);
    assert_eq!(fb.width(), 0);
    assert_eq!(fb.height(), 0);
    assert!(fb.cell_at(0, 0).is_none());

    // Test with zero width
    let fb = FrameBuffer::new(0, 10);
    assert_eq!(fb.width(), 0);
    assert!(fb.cell_at(0, 0).is_none());

    // Test with zero height
    let fb = FrameBuffer::new(10, 0);
    assert_eq!(fb.height(), 0);
    assert!(fb.cell_at(0, 0).is_none());
}

#[test]
fn test_parser_malformed_escape_sequences() {
    let mut parser = Parser::new();
    let mut fb = FrameBuffer::new(80, 24);

    // Test incomplete escape sequences
    let incomplete_sequences = [
        b"\x1b[".as_ref(),
        b"\x1b[3".as_ref(),
        b"\x1b[38;5".as_ref(),
        b"\x1b[38;5;".as_ref(),
        b"\x1b]".as_ref(),
        b"\x1b]0".as_ref(),
        b"\x1b(".as_ref(),
    ];

    for seq in &incomplete_sequences {
        for &byte in seq.iter() {
            parser.advance(&mut fb, byte);
        }
        // Should not panic, parser should handle gracefully
    }

    // Test invalid escape sequences
    let invalid_sequences = [
        b"\x1b[999999999999999999m".as_ref(), // Huge number
        b"\x1b[38;5;999m".as_ref(),           // Invalid color index
        b"\x1b[38;2;999;999;999m".as_ref(),   // RGB values out of range
        b"\x1b[;;;;;m".as_ref(),              // Multiple semicolons
        b"\x1b[\x00m".as_ref(),               // Null byte in sequence
        b"\x1b[38;5m".as_ref(),               // Missing color value
    ];

    for seq in &invalid_sequences {
        for &byte in seq.iter() {
            parser.advance(&mut fb, byte);
        }
        // Should handle gracefully
    }
}

#[test]
fn test_parser_invalid_utf8() {
    let mut parser = Parser::new();
    let mut fb = FrameBuffer::new(80, 24);

    // Invalid UTF-8 sequences
    let invalid_utf8_sequences = [
        vec![0xFF, 0xFE],             // Invalid start bytes
        vec![0xC0, 0x80],             // Overlong encoding
        vec![0xE0, 0x80, 0x80],       // Overlong encoding
        vec![0xF4, 0x90, 0x80, 0x80], // Out of range
        vec![0xED, 0xA0, 0x80],       // Surrogate half
        vec![0xC2],                   // Incomplete sequence
        vec![0xE0, 0xA0],             // Incomplete sequence
        vec![0xF0, 0x90, 0x80],       // Incomplete sequence
    ];

    for seq in &invalid_utf8_sequences {
        for &byte in seq.iter() {
            parser.advance(&mut fb, byte);
        }
        // Should handle gracefully, likely replacing with replacement character
    }
}

#[test]
fn test_terminal_resize_edge_cases() {
    let mut terminal = Terminal::new(80, 24);

    // Test resize to zero dimensions - should fail
    assert!(terminal.resize(0, 0).is_err());
    assert!(terminal.resize(80, 0).is_err());
    assert!(terminal.resize(0, 24).is_err());

    // Test resize to very large dimensions
    assert!(terminal.resize(u16::MAX, u16::MAX).is_ok());
    // Implementation might cap at reasonable values

    // Test multiple rapid resizes
    for size in &[(10, 10), (100, 40), (80, 24), (1, 1), (200, 60)] {
        assert!(terminal.resize(size.0, size.1).is_ok());
    }
}

#[test]
fn test_terminal_state_cursor_bounds() {
    let mut state = TerminalState::new(80, 24);

    // Set cursor out of bounds
    state.cursor_x = 100;
    state.cursor_y = 50;

    // When converting to framebuffer, it should handle gracefully
    let mut fb = FrameBuffer::new(80, 24);
    rosh_terminal::state_to_framebuffer(&state, &mut fb);
    // Should not panic

    // Test with cursor at exact boundary
    state.cursor_x = 79;
    state.cursor_y = 23;
    rosh_terminal::state_to_framebuffer(&state, &mut fb);
    // Should handle correctly
}

#[test]
fn test_parser_buffer_overflow_attempts() {
    let mut parser = Parser::new();
    let mut fb = FrameBuffer::new(80, 24);

    // Try to overflow with very long escape sequence
    let mut long_seq = vec![0x1b, b'['];
    for _ in 0..10000 {
        long_seq.push(b'9');
    }
    long_seq.push(b'm');

    for &byte in long_seq.iter() {
        parser.advance(&mut fb, byte);
    }
    // Should handle without panic or excessive memory use

    // Try to overflow with many parameters
    let mut many_params = vec![0x1b, b'['];
    for i in 0..1000 {
        if i > 0 {
            many_params.push(b';');
        }
        many_params.push(b'1');
    }
    many_params.push(b'm');

    for &byte in many_params.iter() {
        parser.advance(&mut fb, byte);
    }
    // Should handle gracefully
}

#[test]
fn test_terminal_title_edge_cases() {
    let mut terminal = Terminal::new(80, 24);

    // Test empty title
    terminal.set_title(String::new());
    assert_eq!(terminal.title(), "");

    // Test very long title
    let long_title = "X".repeat(10000);
    terminal.set_title(long_title.clone());
    // Should handle without panic, might truncate

    // Test title with special characters
    let special_title = "Title\x00\x01\x02\n\r\t";
    terminal.set_title(special_title.to_string());
    // Should handle gracefully

    // Test title with invalid UTF-8 (using String::from_utf8_lossy)
    let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
    let title = String::from_utf8_lossy(&invalid_utf8).to_string();
    terminal.set_title(title);
    // Should handle gracefully
}

#[test]
fn test_parser_control_characters() {
    let mut parser = Parser::new();
    let mut fb = FrameBuffer::new(80, 24);

    // Test all control characters
    for byte in 0..32u8 {
        parser.advance(&mut fb, byte);
        // Should handle each control character appropriately
    }

    // Test DEL character
    parser.advance(&mut fb, 0x7F);

    // Test high control characters (C1)
    for byte in 0x80..0xA0u8 {
        parser.advance(&mut fb, byte);
    }
}

#[test]
fn test_framebuffer_clear_operations() {
    let mut fb = FrameBuffer::new(10, 10);

    // Test clear operations
    fb.clear();
    for y in 0..10 {
        for x in 0..10 {
            assert_eq!(fb.cell_at(x, y).unwrap().c, ' ');
        }
    }

    // Test clear to cursor
    fb.clear_to_cursor();

    // Test that appropriate cells are cleared
    for y in 0..10 {
        for x in 0..10 {
            assert_eq!(fb.cell_at(x, y).unwrap().c, ' ');
        }
    }
}

#[test]
fn test_terminal_state_serialization_errors() {
    // Test serializing very large state
    let mut state = TerminalState::new(1000, 1000);

    // Fill with data
    state.title = "X".repeat(1000);

    // Try to serialize with small buffer
    let result = rkyv::to_bytes::<_, 16>(&state);
    // rkyv may or may not fail with small buffers - it depends on data size
    // Just check that it doesn't panic
    let _ = result;

    // Serialize normally
    let serialized = rkyv::to_bytes::<_, 65536>(&state).expect("Should serialize");

    // Corrupt and try to deserialize
    let mut corrupted = serialized.to_vec();
    if corrupted.len() > 100 {
        for i in 50..100 {
            corrupted[i] = 0xFF;
        }
    }

    let result = rkyv::check_archived_root::<TerminalState>(&corrupted);
    // rkyv validation might not catch all corruptions
    // Just check that it doesn't panic
    let _ = result;
}

#[test]
fn test_parser_osc_sequences() {
    let mut parser = Parser::new();
    let mut fb = FrameBuffer::new(80, 24);

    // Test OSC sequences (Operating System Command)
    let osc_sequences = [
        b"\x1b]0;Terminal Title\x07".as_ref(),    // Set title with BEL
        b"\x1b]0;Terminal Title\x1b\\".as_ref(),  // Set title with ST
        b"\x1b]2;Another Title\x07".as_ref(),     // Set window title
        b"\x1b]0;\x07".as_ref(),                  // Empty title
        b"\x1b]999;Unknown Command\x07".as_ref(), // Unknown OSC
    ];

    for seq in &osc_sequences {
        for &byte in seq.iter() {
            parser.advance(&mut fb, byte);
        }
        // Should handle gracefully
    }

    // Test incomplete OSC
    for &byte in b"\x1b]0;Incomplete".iter() {
        parser.advance(&mut fb, byte);
    }
    // Should buffer and wait for terminator

    // Test very long OSC
    let mut long_osc = vec![0x1b, b']', b'0', b';'];
    long_osc.extend(vec![b'X'; 10000]);
    long_osc.push(0x07);
    for &byte in long_osc.iter() {
        parser.advance(&mut fb, byte);
    }
    // Should handle without excessive memory use
}

#[test]
fn test_terminal_color_edge_cases() {
    let mut parser = Parser::new();
    let mut fb = FrameBuffer::new(80, 24);

    // Test 256-color mode edge cases
    for &byte in b"\x1b[38;5;0m".iter() {
        parser.advance(&mut fb, byte);
    }
    for &byte in b"\x1b[38;5;255m".iter() {
        parser.advance(&mut fb, byte);
    }
    for &byte in b"\x1b[38;5;256m".iter() {
        parser.advance(&mut fb, byte);
    }

    for &byte in b"\x1b[48;5;0m".iter() {
        parser.advance(&mut fb, byte);
    }
    for &byte in b"\x1b[48;5;255m".iter() {
        parser.advance(&mut fb, byte);
    }
    for &byte in b"\x1b[48;5;300m".iter() {
        parser.advance(&mut fb, byte);
    }

    // Test true color mode edge cases
    for &byte in b"\x1b[38;2;0;0;0m".iter() {
        parser.advance(&mut fb, byte);
    }
    for &byte in b"\x1b[38;2;255;255;255m".iter() {
        parser.advance(&mut fb, byte);
    }
    for &byte in b"\x1b[38;2;256;256;256m".iter() {
        parser.advance(&mut fb, byte);
    }
    for &byte in b"\x1b[38;2;1000;1000;1000m".iter() {
        parser.advance(&mut fb, byte);
    }

    // Missing components
    for &byte in b"\x1b[38;2;255;255m".iter() {
        parser.advance(&mut fb, byte);
    }
    for &byte in b"\x1b[38;2;255m".iter() {
        parser.advance(&mut fb, byte);
    }
    for &byte in b"\x1b[38;2m".iter() {
        parser.advance(&mut fb, byte);
    }
}

#[test]
fn test_cell_creation() {
    // Test creating cells with different attributes
    let cell = Cell {
        c: 'A',
        fg: Color::Default,
        bg: Color::Default,
        attrs: Attributes::default(),
    };
    assert_eq!(cell.c, 'A');

    // Test default cell
    let default_cell = Cell::default();
    assert_eq!(default_cell.c, ' ');
}
