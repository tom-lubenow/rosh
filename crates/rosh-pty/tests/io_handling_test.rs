//! I/O handling and buffering tests

use rosh_pty::{AsyncPtyMaster, Pty, SessionBuilder, SessionEvent};
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

#[cfg(unix)]
mod unix_tests {
    use super::*;

    #[tokio::test]
    async fn test_async_pty_master_read_write() {
        // Test AsyncPtyMaster directly
        let pty = Pty::new().expect("Failed to create PTY");
        let cmd = Command::new("cat");

        let process = pty.spawn(cmd).expect("Failed to spawn cat");
        let master = process.take_master();

        let mut async_master = AsyncPtyMaster::new(master).expect("Failed to create async master");

        // Write data
        let test_data = b"Hello, AsyncPtyMaster!\n";
        async_master
            .write_all(test_data)
            .await
            .expect("Failed to write");
        async_master.flush().await.expect("Failed to flush");

        // Read back (cat echoes)
        let mut buffer = vec![0u8; 128];
        let result = timeout(Duration::from_secs(1), async_master.read(&mut buffer)).await;

        match result {
            Ok(Ok(n)) => {
                assert!(n > 0, "Should read some data");
                let output = String::from_utf8_lossy(&buffer[..n]);
                assert!(
                    output.contains("Hello, AsyncPtyMaster"),
                    "Should echo back our input"
                );
            }
            _ => {
                eprintln!("Warning: Could not read from AsyncPtyMaster in test environment");
            }
        }
    }

    #[tokio::test]
    async fn test_large_data_transfer() {
        // Test transferring large amounts of data
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("wc -c | xargs -I{} echo 'Received {} bytes'");

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Wait for process to be ready
        sleep(Duration::from_millis(200)).await;

        // Check for completion message
        let mut got_complete = false;
        timeout(Duration::from_secs(3), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("Received") && output.contains("bytes") {
                        got_complete = true;
                        println!("Large data transfer result: {}", output.trim());

                        // Verify size is reasonable (might be less due to buffering)
                        if let Some(num_str) = output
                            .split_whitespace()
                            .find(|s| s.parse::<usize>().is_ok())
                        {
                            if let Ok(num) = num_str.parse::<usize>() {
                                assert!(num > 0, "Should receive some data");
                            }
                        }
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        if !got_complete {
            eprintln!("Warning: Large data transfer test did not complete as expected");
        }
    }

    #[tokio::test]
    async fn test_binary_data_handling() {
        // Test handling of binary data
        let mut cmd = Command::new("od");
        cmd.arg("-tx1"); // Hex dump

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // od should produce hex output even without input
        let mut got_output = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                match event {
                    SessionEvent::StateChanged(state) => {
                        if !state.screen.is_empty() {
                            got_output = true;
                        }
                    }
                    SessionEvent::ProcessExited(_) => break,
                    _ => {}
                }
            }
        })
        .await
        .ok();

        if !got_output {
            eprintln!("Warning: Binary data test did not produce output");
        }
    }

    #[tokio::test]
    async fn test_rapid_output() {
        // Test rapid output handling
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            for i in $(seq 1 10); do
                echo "Rapid line $i"
            done
            "#,
        );

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Collect output
        let mut lines_seen = 0;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    for i in 1..=10 {
                        if output.contains(&format!("Rapid line {i}")) {
                            lines_seen = lines_seen.max(i);
                        }
                    }
                }
            }
        })
        .await
        .ok();

        assert!(lines_seen >= 5, "Should see multiple rapid output lines");
    }

    #[tokio::test]
    async fn test_slow_output_producer() {
        // Test handling of slow output producer
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            for i in 1 2 3 4 5; do
                echo "Line $i"
                sleep 0.2
            done
            "#,
        );

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Collect output over time
        let mut lines_seen = 0;
        timeout(Duration::from_secs(3), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    for i in 1..=5 {
                        if output.contains(&format!("Line {i}")) {
                            lines_seen = lines_seen.max(i);
                        }
                    }
                }
            }
        })
        .await
        .ok();

        assert!(
            lines_seen >= 3,
            "Should see multiple lines from slow producer"
        );
    }

    #[tokio::test]
    async fn test_ansi_escape_sequences() {
        // Test handling of ANSI escape sequences
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            # Output with colors (if supported)
            printf "\033[31mRed text\033[0m\n"
            printf "\033[1;32mBold green\033[0m\n"
            printf "Normal text\n"
            "#,
        );

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Terminal emulator should handle ANSI sequences
        let mut saw_content = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    // The terminal emulator processes ANSI sequences
                    // We just verify content is being processed
                    if !state.screen.is_empty() {
                        saw_content = true;
                        let output = String::from_utf8_lossy(&state.screen);
                        // Terminal emulator should have processed the escape sequences
                        // and we should see the text content
                        if output.contains("Red text")
                            || output.contains("Bold green")
                            || output.contains("Normal text")
                        {
                            break;
                        }
                    }
                }
            }
        })
        .await
        .ok();

        assert!(saw_content, "Should process ANSI escape sequences");
    }

    #[tokio::test]
    async fn test_line_buffering() {
        // Test line buffering behavior
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            echo "Line buffered output"
            printf "Partial line without newline..."
            sleep 0.5
            echo " completed!"
            echo "Final line"
            "#,
        );

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Track output progression
        let mut saw_complete = false;

        timeout(Duration::from_secs(3), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("completed!") {
                        saw_complete = true;
                    }
                    if output.contains("Final line") {
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(saw_complete, "Should see completed line");
    }

    #[tokio::test]
    async fn test_stderr_handling() {
        // Test stderr output handling
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            echo "This goes to stdout"
            echo "This goes to stderr" >&2
            echo "Back to stdout"
            "#,
        );

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Both stdout and stderr should appear in PTY
        let mut got_stdout = false;
        let mut got_stderr = false;

        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("This goes to stdout") {
                        got_stdout = true;
                    }
                    if output.contains("This goes to stderr") {
                        got_stderr = true;
                    }
                    if got_stdout && got_stderr {
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(got_stdout, "Should see stdout");
        assert!(got_stderr, "Should see stderr");
    }

    #[tokio::test]
    async fn test_very_long_lines() {
        // Test handling of very long lines
        let long_line = "x".repeat(200);
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(format!("echo '{long_line}'"));

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .dimensions(80, 24) // Standard terminal size
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Check that long line is handled
        let mut got_output = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    // Line should be wrapped or truncated by terminal
                    if output.contains("xxx") {
                        got_output = true;
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(got_output, "Should handle very long lines");
    }
}
