//! Error handling tests for rosh-state module

use rosh_state::{
    AdaptiveCompressor, CompressionAlgorithm, Compressor, StateDiff, StateMessage,
    StateSynchronizer,
};
use rosh_terminal::TerminalState;

#[test]
fn test_compression_errors() {
    // Test individual compressors
    let compressors = vec![
        Compressor::new(CompressionAlgorithm::Zstd),
        Compressor::new(CompressionAlgorithm::Lz4),
    ];

    for compressor in &compressors {
        // Test compressing empty data
        let compressed = compressor.compress(&[]).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, Vec::<u8>::new());

        // Test decompressing corrupted data
        let data = b"Hello, world!";
        let compressed = compressor.compress(data).unwrap();

        // Corrupt the compressed data
        if compressed.len() > 4 {
            let mut corrupted = compressed.clone();
            corrupted[2] ^= 0xFF;
            corrupted[3] ^= 0xFF;

            let result = compressor.decompress(&corrupted);
            // Compression algorithms might or might not detect corruption
            // Some algorithms have built-in checksums, others don't
            // We'll just check that it doesn't panic
            let _ = result;
        }

        // Test decompressing random data
        let random_data = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        let result = compressor.decompress(&random_data);
        // Decompression might fail or produce garbage
        // We just check that it doesn't panic
        let _ = result;
    }
}

#[test]
fn test_adaptive_compressor() {
    let compressor = AdaptiveCompressor::new();

    // Test small data (should use LZ4)
    let small_data = b"Small data";
    let (algo, compressed) = compressor.compress(small_data).unwrap();
    let decompressed = compressor.decompress(algo, &compressed).unwrap();
    assert_eq!(decompressed, small_data);

    // Test large data (should use Zstd)
    let large_data = vec![b'A'; 2048];
    let (algo, compressed) = compressor.compress(&large_data).unwrap();
    let decompressed = compressor.decompress(algo, &compressed).unwrap();
    assert_eq!(decompressed, large_data);
}

#[test]
fn test_state_diff_apply_errors() {
    // Create initial state
    let mut state1 = TerminalState::new(80, 24);
    state1.cursor_x = 10;
    state1.cursor_y = 5;
    state1.title = "Terminal 1".to_string();

    // Create a very different state
    let mut state2 = TerminalState::new(120, 40); // Different dimensions
    state2.cursor_x = 50;
    state2.cursor_y = 20;
    state2.title = "Terminal 2".to_string();

    // Create diff from state1 to state2
    let diff = StateDiff::generate(&state1, &state2).unwrap();

    // Try to apply diff to wrong base state (different dimensions)
    let wrong_base = TerminalState::new(60, 30);
    let result = diff.apply(&wrong_base);

    // This should either fail or produce a state with mismatched expectations
    match result {
        Ok(new_state) => {
            // If it succeeds, the dimensions should match the diff's target
            assert_eq!(new_state.width, state2.width);
            assert_eq!(new_state.height, state2.height);
        }
        Err(_) => {
            // Expected failure when applying to incompatible base
        }
    }
}

#[test]
fn test_state_synchronizer_sequence_errors() {
    let initial_state = TerminalState::new(80, 24);
    let mut sync = StateSynchronizer::new(initial_state.clone(), true);

    // Process acks out of order
    sync.process_ack(5); // Ack for sequence we haven't sent
    sync.process_ack(0); // Should be ignored

    // Update state
    let mut new_state = initial_state.clone();
    new_state.cursor_x = 10;
    let _ = sync.update_state(new_state);

    // The synchronizer should handle out-of-order acks gracefully
}

#[test]
fn test_state_message_serialization_errors() {
    let state = TerminalState::new(80, 24);
    let msg = StateMessage::FullState { seq: 1, state };

    // Serialize
    let serialized = rkyv::to_bytes::<_, 1024>(&msg).expect("Should serialize");

    // Corrupt the data
    let mut corrupted = serialized.to_vec();
    if corrupted.len() > 10 {
        // Corrupt in the middle
        for i in 5..10 {
            corrupted[i] = 0xFF;
        }
    }

    // Try to validate corrupted data
    // rkyv validation might not catch all corruptions
    let _ = rkyv::check_archived_root::<StateMessage>(&corrupted);

    // Test with truncated data
    let truncated = &serialized[..serialized.len() / 2];
    let result = rkyv::check_archived_root::<StateMessage>(truncated);
    assert!(
        result.is_err(),
        "Should fail to validate truncated state message"
    );
}

#[test]
fn test_compression_large_data() {
    let compressor = Compressor::new(CompressionAlgorithm::Zstd);

    // Test with large repetitive data (highly compressible)
    let large_data = vec![b'A'; 1024 * 1024]; // 1MB of 'A's
    let compressed = compressor.compress(&large_data).unwrap();
    assert!(
        compressed.len() < large_data.len() / 10,
        "Should compress repetitive data significantly"
    );

    let decompressed = compressor.decompress(&compressed).unwrap();
    assert_eq!(decompressed, large_data);

    // Test with random data (less compressible)
    let mut random_data = vec![0u8; 100_000];
    for (i, byte) in random_data.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    let compressed = compressor.compress(&random_data).unwrap();
    let decompressed = compressor.decompress(&compressed).unwrap();
    assert_eq!(decompressed, random_data);
}

#[test]
fn test_state_synchronizer_concurrent_updates() {
    let initial_state = TerminalState::new(80, 24);
    let mut sync = StateSynchronizer::new(initial_state, true);

    // Simulate rapid state changes
    for i in 0..10 {
        let mut new_state = sync.current_state().clone();
        new_state.cursor_x = i;
        new_state.title = format!("Title {i}");
        let _ = sync.update_state(new_state);
    }

    // The synchronizer should handle rapid updates gracefully
    let final_state = sync.current_state();
    assert_eq!(final_state.cursor_x, 9);
    assert_eq!(final_state.title, "Title 9");
}

#[test]
fn test_state_diff_edge_cases() {
    // Test diff between identical states
    let state = TerminalState::new(80, 24);
    let diff = StateDiff::generate(&state, &state).unwrap();

    // Diff should be minimal
    let applied = diff.apply(&state).unwrap();
    assert_eq!(applied.cursor_x, state.cursor_x);
    assert_eq!(applied.cursor_y, state.cursor_y);
    assert_eq!(applied.title, state.title);

    // Test diff with only cursor position change
    let mut state2 = state.clone();
    state2.cursor_x = 40;
    state2.cursor_y = 12;

    let diff = StateDiff::generate(&state, &state2).unwrap();
    let applied = diff.apply(&state).unwrap();
    assert_eq!(applied.cursor_x, 40);
    assert_eq!(applied.cursor_y, 12);

    // Test diff with terminal resize
    let state3 = TerminalState::new(120, 40);
    let diff = StateDiff::generate(&state, &state3).unwrap();
    let applied = diff.apply(&state).unwrap();
    assert_eq!(applied.width, 120);
    assert_eq!(applied.height, 40);
}

#[test]
fn test_compression_algorithm_consistency() {
    let data = b"Test data for compression consistency";
    let algorithms = [CompressionAlgorithm::Zstd, CompressionAlgorithm::Lz4];

    for algo in &algorithms {
        let compressor = Compressor::new(*algo);

        // Compress and decompress multiple times
        for _ in 0..3 {
            let compressed1 = compressor.compress(data).unwrap();
            let compressed2 = compressor.compress(data).unwrap();

            // Compressed data might differ due to compression internals
            // but decompressed data must be identical
            let decompressed1 = compressor.decompress(&compressed1).unwrap();
            let decompressed2 = compressor.decompress(&compressed2).unwrap();

            assert_eq!(decompressed1, data);
            assert_eq!(decompressed2, data);
        }
    }
}

#[test]
fn test_state_predictor_errors() {
    use rosh_state::{KeyCode, Predictor, UserInput};

    let initial_state = TerminalState::new(80, 24);
    let mut predictor = Predictor::new(initial_state.clone());

    // Test prediction with character input
    predictor.predict_input(UserInput::Character('A'));
    assert_eq!(predictor.pending_predictions(), 1);

    // Test prediction with key input
    predictor.predict_input(UserInput::Key(KeyCode::Backspace));
    assert_eq!(predictor.pending_predictions(), 2);

    // Test getting predicted state
    let _predicted = predictor.predicted_state();
    // Should have applied predictions

    // Test confirming predictions
    predictor.update_confirmed(initial_state.clone(), 1);
    assert_eq!(predictor.pending_predictions(), 1);
}

#[test]
fn test_compressor_edge_cases() {
    let compressor = Compressor::new(CompressionAlgorithm::Zstd);

    // Test compression of data that expands
    let incompressible = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]; // Small random data
    let compressed = compressor.compress(&incompressible).unwrap();
    // Compressed might be larger than original for small random data

    let decompressed = compressor.decompress(&compressed).unwrap();
    assert_eq!(decompressed, incompressible);

    // Test empty compression
    let empty: &[u8] = &[];
    let compressed = compressor.compress(empty).unwrap();
    let decompressed = compressor.decompress(&compressed).unwrap();
    assert_eq!(decompressed, empty);
}

#[test]
fn test_state_message_types() {
    let state = TerminalState::new(80, 24);

    // Test full state message
    let msg = StateMessage::FullState {
        seq: 1,
        state: state.clone(),
    };

    // Test delta message
    let diff = StateDiff::generate(&state, &state).unwrap();
    let msg2 = StateMessage::Delta {
        seq: 2,
        delta: diff,
    };

    // Test ack message
    let msg3 = StateMessage::Ack(3);

    // Verify we can match on messages
    match msg {
        StateMessage::FullState { seq, state: _ } => {
            assert_eq!(seq, 1);
        }
        _ => panic!("Expected FullState"),
    }

    match msg2 {
        StateMessage::Delta { seq, delta: _ } => {
            assert_eq!(seq, 2);
        }
        _ => panic!("Expected Delta"),
    }

    match msg3 {
        StateMessage::Ack(seq) => {
            assert_eq!(seq, 3);
        }
        _ => panic!("Expected Ack"),
    }
}
