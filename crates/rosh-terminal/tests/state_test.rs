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

    #[test]
    fn test_terminal_state_maximum_dimensions() {
        // Test with maximum u16 dimensions
        let max_dim = u16::MAX;
        let state = TerminalState::new(max_dim, 1);
        assert_eq!(state.width, max_dim);
        assert_eq!(state.height, 1);
        // Screen size would be u16::MAX * 1 = 65535 bytes
        assert_eq!(state.screen.len(), max_dim as usize);

        // Test that we can handle reasonably large dimensions
        let large = TerminalState::new(1000, 1000);
        assert_eq!(large.screen.len(), 1_000_000);
        assert_eq!(large.attributes.len(), 1_000_000);
    }

    #[test]
    fn test_terminal_state_cursor_overflow() {
        // Test cursor positions that might overflow
        let mut state = TerminalState::new(100, 100);

        // Set cursor to maximum valid position
        state.cursor_x = 99;
        state.cursor_y = 99;

        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");

        assert_eq!(restored.cursor_x, 99);
        assert_eq!(restored.cursor_y, 99);

        // Test with cursor positions beyond screen bounds
        // (This is allowed by the data structure, bounds checking would be in emulator)
        state.cursor_x = 200;
        state.cursor_y = 200;

        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");

        assert_eq!(restored.cursor_x, 200);
        assert_eq!(restored.cursor_y, 200);
    }

    #[test]
    fn test_terminal_state_concurrent_serialization() {
        use std::sync::Arc;
        use std::thread;

        let state = Arc::new(TerminalState::new(80, 24));
        let mut handles = vec![];

        // Spawn multiple threads to serialize the same state
        for _ in 0..10 {
            let state_clone = Arc::clone(&state);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let bytes = state_clone.to_bytes().expect("Should serialize");
                    let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");
                    assert_eq!(restored, *state_clone);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete");
        }
    }

    #[test]
    fn test_terminal_state_partial_screen_modifications() {
        let mut state = TerminalState::new(10, 10);

        // Modify screen in patterns
        for y in 0..10 {
            for x in 0..10 {
                let index = y * 10 + x;
                if (x + y) % 2 == 0 {
                    state.screen[index] = b'#';
                    state.attributes[index] = 0xFF;
                }
            }
        }

        // Verify checkerboard pattern
        for y in 0..10 {
            for x in 0..10 {
                let index = y * 10 + x;
                if (x + y) % 2 == 0 {
                    assert_eq!(state.screen[index], b'#');
                    assert_eq!(state.attributes[index], 0xFF);
                } else {
                    assert_eq!(state.screen[index], b' ');
                    assert_eq!(state.attributes[index], 0);
                }
            }
        }

        // Serialize and verify pattern is preserved
        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");
        assert_eq!(restored.screen, state.screen);
        assert_eq!(restored.attributes, state.attributes);
    }

    #[test]
    fn test_terminal_state_scrollback_limits() {
        let mut state = TerminalState::new(80, 24);

        // Add a very large scrollback buffer
        for i in 0..10000 {
            let line =
                format!("This is scrollback line {i} with some extra content to make it longer");
            state.scrollback.push(line.into_bytes());
        }

        assert_eq!(state.scrollback.len(), 10000);

        // Serialize - this tests handling of large data
        let bytes = state.to_bytes().expect("Should serialize");
        assert!(bytes.len() > 10000); // Should be reasonably large

        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");
        assert_eq!(restored.scrollback.len(), 10000);

        // Verify some samples
        assert!(restored.scrollback[0].starts_with(b"This is scrollback line 0"));
        assert!(restored.scrollback[9999].starts_with(b"This is scrollback line 9999"));
    }

    #[test]
    fn test_terminal_state_attribute_combinations() {
        let mut state = TerminalState::new(5, 5);

        // Test all possible attribute combinations for a small area
        for i in 0..25 {
            state.attributes[i] = i as u8;
            state.screen[i] = b'A' + (i as u8 % 26);
        }

        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");

        // Verify all attributes are preserved exactly
        for i in 0..25 {
            assert_eq!(restored.attributes[i], i as u8);
            assert_eq!(restored.screen[i], b'A' + (i as u8 % 26));
        }
    }

    #[test]
    fn test_terminal_state_title_edge_cases() {
        let mut state = TerminalState::new(80, 24);

        // Test empty title (already covered but let's be explicit)
        state.title = String::new();
        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");
        assert_eq!(restored.title, "");

        // Test very long title
        state.title = "A".repeat(10000);
        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");
        assert_eq!(restored.title.len(), 10000);
        assert!(restored.title.chars().all(|c| c == 'A'));

        // Test title with special characters
        state.title = "\0\n\r\t\x1b[31mRed\x1b[0m".to_string();
        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");
        assert_eq!(restored.title, "\0\n\r\t\x1b[31mRed\x1b[0m");
    }

    #[test]
    fn test_terminal_state_mixed_content() {
        let mut state = TerminalState::new(40, 20);

        // Fill with mixed ASCII and high bytes
        for i in 0..state.screen.len() {
            state.screen[i] = (i % 256) as u8;
            state.attributes[i] = ((i / 256) % 256) as u8;
        }

        // Add diverse scrollback
        state.scrollback.push(vec![0u8; 100]); // All nulls
        state.scrollback.push(vec![255u8; 100]); // All 0xFF
        state.scrollback.push((0..=255).collect()); // All byte values

        // Complex title
        state.title = format!(
            "Test {} Terminal {}",
            char::from_u32(0x1F980).unwrap(),
            "🔧"
        );

        // Cursor at specific position
        state.cursor_x = 39;
        state.cursor_y = 19;
        state.cursor_visible = false;

        let bytes = state.to_bytes().expect("Should serialize");
        let restored = TerminalState::from_bytes(&bytes).expect("Should deserialize");

        // Verify everything is preserved
        assert_eq!(restored.screen, state.screen);
        assert_eq!(restored.attributes, state.attributes);
        assert_eq!(restored.scrollback, state.scrollback);
        assert_eq!(restored.title, state.title);
        assert_eq!(restored.cursor_x, 39);
        assert_eq!(restored.cursor_y, 19);
        assert!(!restored.cursor_visible);
    }

    #[test]
    fn test_terminal_state_serialization_stability() {
        // Test that serializing the same state multiple times produces the same bytes
        let mut state = TerminalState::new(80, 24);
        state.cursor_x = 10;
        state.cursor_y = 5;
        state.title = "Stable".to_string();
        state.screen[100] = b'X';
        state.attributes[100] = 42;
        state.scrollback.push(vec![b'T', b'e', b's', b't']);

        let bytes1 = state.to_bytes().expect("Should serialize");
        let bytes2 = state.to_bytes().expect("Should serialize");
        let bytes3 = state.to_bytes().expect("Should serialize");

        // All serializations should produce identical bytes
        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);
    }
}
