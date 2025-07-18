//! Tests for TerminalState

use rosh_terminal::TerminalState;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_state_new() {
        let state = TerminalState::new(80, 24);

        assert_eq!(state.width, 80);
        assert_eq!(state.height, 24);
        assert_eq!(state.screen.len(), 80 * 24);
        assert_eq!(state.attributes.len(), 80 * 24);
        assert_eq!(state.cursor_x, 0);
        assert_eq!(state.cursor_y, 0);
        assert!(state.cursor_visible);
        assert!(state.title.is_empty());
        assert!(state.scrollback.is_empty());

        // Check that screen is filled with spaces
        assert!(state.screen.iter().all(|&b| b == b' '));
        // Check that attributes are all zero
        assert!(state.attributes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_terminal_state_different_sizes() {
        // Test small terminal
        let small = TerminalState::new(10, 5);
        assert_eq!(small.screen.len(), 50);
        assert_eq!(small.attributes.len(), 50);

        // Test large terminal
        let large = TerminalState::new(200, 60);
        assert_eq!(large.screen.len(), 12000);
        assert_eq!(large.attributes.len(), 12000);

        // Test minimum size
        let min = TerminalState::new(1, 1);
        assert_eq!(min.screen.len(), 1);
        assert_eq!(min.attributes.len(), 1);
    }

    #[test]
    fn test_terminal_state_serialization() {
        let mut state = TerminalState::new(80, 24);
        state.cursor_x = 10;
        state.cursor_y = 5;
        state.cursor_visible = false;
        state.title = "Test Terminal".to_string();

        // Add some content
        state.screen[0] = b'H';
        state.screen[1] = b'e';
        state.screen[2] = b'l';
        state.screen[3] = b'l';
        state.screen[4] = b'o';

        // Add scrollback
        state
            .scrollback
            .push(vec![b'L', b'i', b'n', b'e', b' ', b'1']);
        state
            .scrollback
            .push(vec![b'L', b'i', b'n', b'e', b' ', b'2']);

        // Serialize
        let bytes = state.to_bytes().expect("Should serialize");
        assert!(!bytes.is_empty());

        // Deserialize
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");

        // Verify all fields
        assert_eq!(restored.width, state.width);
        assert_eq!(restored.height, state.height);
        assert_eq!(restored.cursor_x, state.cursor_x);
        assert_eq!(restored.cursor_y, state.cursor_y);
        assert_eq!(restored.cursor_visible, state.cursor_visible);
        assert_eq!(restored.title, state.title);
        assert_eq!(restored.screen, state.screen);
        assert_eq!(restored.attributes, state.attributes);
        assert_eq!(restored.scrollback, state.scrollback);
    }

    #[test]
    fn test_terminal_state_equality() {
        let state1 = TerminalState::new(80, 24);
        let state2 = TerminalState::new(80, 24);
        let state3 = TerminalState::new(100, 30);

        // Same dimensions should be equal
        assert_eq!(state1, state2);

        // Different dimensions should not be equal
        assert_ne!(state1, state3);

        // Modify one state
        let mut state4 = TerminalState::new(80, 24);
        state4.cursor_x = 5;
        assert_ne!(state1, state4);
    }

    #[test]
    fn test_terminal_state_clone() {
        let mut original = TerminalState::new(80, 24);
        original.cursor_x = 10;
        original.cursor_y = 5;
        original.title = "Original".to_string();
        original.screen[0] = b'X';
        original.scrollback.push(vec![b'T', b'e', b's', b't']);

        let cloned = original.clone();

        // Verify clone is identical
        assert_eq!(cloned.width, original.width);
        assert_eq!(cloned.height, original.height);
        assert_eq!(cloned.cursor_x, original.cursor_x);
        assert_eq!(cloned.cursor_y, original.cursor_y);
        assert_eq!(cloned.title, original.title);
        assert_eq!(cloned.screen, original.screen);
        assert_eq!(cloned.scrollback, original.scrollback);

        // Verify it's a deep clone
        let mut modified = original.clone();
        modified.cursor_x = 20;
        modified.screen[0] = b'Y';
        assert_ne!(modified.cursor_x, original.cursor_x);
        assert_ne!(modified.screen[0], original.screen[0]);
    }

    #[test]
    fn test_terminal_state_with_attributes() {
        let mut state = TerminalState::new(10, 2);

        // Set some attributes
        state.attributes[0] = 0x01; // Bold
        state.attributes[1] = 0x02; // Dim
        state.attributes[2] = 0x04; // Italic
        state.attributes[3] = 0x08; // Underline

        // Serialize and deserialize
        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");

        // Verify attributes are preserved
        assert_eq!(restored.attributes[0], 0x01);
        assert_eq!(restored.attributes[1], 0x02);
        assert_eq!(restored.attributes[2], 0x04);
        assert_eq!(restored.attributes[3], 0x08);
    }

    #[test]
    fn test_terminal_state_large_scrollback() {
        let mut state = TerminalState::new(80, 24);

        // Add many scrollback lines
        for i in 0..1000 {
            let line = format!("Line {i}").into_bytes();
            state.scrollback.push(line);
        }

        assert_eq!(state.scrollback.len(), 1000);

        // Serialize and deserialize
        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");

        // Verify scrollback is preserved
        assert_eq!(restored.scrollback.len(), 1000);
        assert_eq!(restored.scrollback[0], "Line 0".as_bytes());
        assert_eq!(restored.scrollback[999], "Line 999".as_bytes());
    }

    #[test]
    fn test_terminal_state_unicode_title() {
        let mut state = TerminalState::new(80, 24);
        state.title = "🦀 Rust Terminal 终端 🚀".to_string();

        // Serialize and deserialize
        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");

        // Verify Unicode title is preserved
        assert_eq!(restored.title, "🦀 Rust Terminal 终端 🚀");
    }

    #[test]
    fn test_terminal_state_full_screen_content() {
        let mut state = TerminalState::new(3, 3);

        // Fill screen with pattern
        let pattern = b"ABCDEFGHI";
        for (i, &byte) in pattern.iter().enumerate() {
            state.screen[i] = byte;
            state.attributes[i] = (i as u8) + 1;
        }

        // Serialize and deserialize
        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");

        // Verify content
        assert_eq!(&restored.screen[..], pattern);
        for i in 0..9 {
            assert_eq!(restored.attributes[i], (i as u8) + 1);
        }
    }

    #[test]
    fn test_terminal_state_edge_cursor_positions() {
        let mut state = TerminalState::new(80, 24);

        // Test cursor at bottom-right
        state.cursor_x = 79;
        state.cursor_y = 23;

        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");

        assert_eq!(restored.cursor_x, 79);
        assert_eq!(restored.cursor_y, 23);

        // Test cursor at various positions
        let positions = [(0, 0), (40, 12), (79, 0), (0, 23)];
        for (x, y) in positions {
            state.cursor_x = x;
            state.cursor_y = y;

            let bytes = state.to_bytes().expect("Should serialize");
            let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");

            assert_eq!(restored.cursor_x, x);
            assert_eq!(restored.cursor_y, y);
        }
    }

    #[test]
    fn test_terminal_state_empty_to_populated() {
        let mut state = TerminalState::new(10, 5);

        // Initially empty
        assert!(state.title.is_empty());
        assert!(state.scrollback.is_empty());

        // Populate
        state.title = "My Terminal".to_string();
        state.scrollback.push(vec![b'H', b'i']);
        state.cursor_visible = false;

        // Fill part of screen
        for i in 0..5 {
            state.screen[i] = b'A' + i as u8;
        }

        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");

        assert_eq!(restored.title, "My Terminal");
        assert_eq!(restored.scrollback.len(), 1);
        assert!(!restored.cursor_visible);
        assert_eq!(restored.screen[0], b'A');
        assert_eq!(restored.screen[4], b'E');
        assert_eq!(restored.screen[5], b' '); // Rest should still be spaces
    }

    #[test]
    fn test_deserialize_invalid_data() {
        // Test with empty data
        let result = TerminalState::from_bytes(&[]);
        assert!(result.is_err());

        // Test with random data
        let random_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let result = TerminalState::from_bytes(&random_data);
        assert!(result.is_err());

        // Test with truncated valid data
        let state = TerminalState::new(80, 24);
        let bytes = state.to_bytes().expect("Should serialize");
        let truncated = &bytes[..bytes.len() / 2];
        let result = TerminalState::from_bytes(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_terminal_state_zero_size() {
        // Even with zero dimensions, state should handle it gracefully
        let state = TerminalState::new(0, 0);
        assert_eq!(state.width, 0);
        assert_eq!(state.height, 0);
        assert_eq!(state.screen.len(), 0);
        assert_eq!(state.attributes.len(), 0);

        // Should still serialize/deserialize
        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");
        assert_eq!(restored.width, 0);
        assert_eq!(restored.height, 0);
    }

    #[test]
    fn test_terminal_state_debug_format() {
        let state = TerminalState::new(80, 24);
        let debug_str = format!("{state:?}");

        // Debug output should contain key information
        assert!(debug_str.contains("TerminalState"));
        assert!(debug_str.contains("width: 80"));
        assert!(debug_str.contains("height: 24"));
        assert!(debug_str.contains("cursor_x: 0"));
        assert!(debug_str.contains("cursor_y: 0"));
    }
}
