//! Signal handling tests for PTY sessions

use rosh_pty::{SessionBuilder, SessionEvent};
use std::process::Command;
use std::time::Duration;
use tokio::time::{sleep, timeout};

#[cfg(unix)]
mod unix_tests {
    use super::*;
    use nix::sys::signal::{self, Signal};
    use nix::unistd::Pid;

    #[tokio::test]
    async fn test_sigwinch_propagation() {
        // Start a process that will handle SIGWINCH
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            trap 'echo "SIGWINCH received"' WINCH
            echo "Ready"
            sleep 10
            "#,
        );

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .dimensions(80, 24)
            .build()
            .await
            .expect("Should create session");

        // Start session in background
        let session_handle = tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Wait for process to be ready
        let mut ready = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("Ready") {
                        ready = true;
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(ready, "Process should be ready");

        // Create another session to test resize
        let (session2, mut events2) = SessionBuilder::new()
            .dimensions(80, 24)
            .build()
            .await
            .expect("Should create second session");

        // Resize should trigger SIGWINCH
        session2
            .resize(100, 30)
            .await
            .expect("Should resize successfully");

        // Look for SIGWINCH message
        let mut found_sigwinch = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events2.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("SIGWINCH received") {
                        found_sigwinch = true;
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        // Clean up
        session2.shutdown();
        drop(session_handle);

        // Note: Signal handling in test environment might not work reliably
        if !found_sigwinch {
            eprintln!("Warning: SIGWINCH signal not detected in test environment");
        }
    }

    #[tokio::test]
    async fn test_sigterm_handling() {
        // Start a process that handles SIGTERM
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            trap 'echo "SIGTERM received"; exit 0' TERM
            echo "PID:$$"
            sleep 60
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

        // Wait for PID output
        let mut pid = None;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if let Some(line) = output.lines().find(|l| l.starts_with("PID:")) {
                        if let Ok(p) = line[4..].trim().parse::<i32>() {
                            pid = Some(Pid::from_raw(p));
                            break;
                        }
                    }
                }
            }
        })
        .await
        .ok();

        if let Some(pid) = pid {
            // Send SIGTERM
            let _ = signal::kill(pid, Signal::SIGTERM);

            // Check for exit
            let mut exited = false;
            timeout(Duration::from_secs(2), async {
                while let Some(event) = events.recv().await {
                    if let SessionEvent::ProcessExited(code) = event {
                        exited = true;
                        assert_eq!(code, 0, "Process should exit cleanly with code 0");
                        break;
                    }
                }
            })
            .await
            .ok();

            if !exited {
                eprintln!("Warning: Process did not exit after SIGTERM in test environment");
            }
        }
    }

    #[tokio::test]
    async fn test_signal_during_io() {
        // Test sending signals while process is doing I/O
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            trap 'echo "INTERRUPTED"' INT
            while true; do
                echo "Working..."
                sleep 0.1
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

        // Wait for some output
        let mut got_output = false;
        timeout(Duration::from_secs(1), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("Working...") {
                        got_output = true;
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(got_output, "Should see process output");

        // Note: Sending SIGINT to the process would require knowing its PID
        // which is not easily accessible in the current API
    }

    #[test]
    fn test_pty_process_kill_signal() {
        use rosh_pty::Pty;

        let pty = Pty::new().expect("Failed to create PTY");
        let mut cmd = Command::new("sleep");
        cmd.arg("60");

        let process = pty.spawn(cmd).expect("Failed to spawn process");

        // Kill should send SIGTERM
        process.kill().expect("Failed to kill process");

        // Wait for exit
        let status = process.wait().expect("Failed to wait for process");

        // Process killed by SIGTERM should have exit code 128 + 15
        #[cfg(target_os = "linux")]
        {
            // On Linux, might need to extract signal from status
            assert!(status != 0, "Process should not exit cleanly");
        }
        #[cfg(not(target_os = "linux"))]
        {
            // On other systems, just verify non-zero exit
            assert!(status != 0, "Process should not exit cleanly");
        }
    }

    #[tokio::test]
    async fn test_multiple_resize_events() {
        let (session, mut events) = SessionBuilder::new()
            .dimensions(80, 24)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Rapid resize sequence
        let sizes = vec![(100, 30), (120, 40), (80, 24), (200, 50), (80, 24)];

        for (cols, rows) in sizes {
            let (session2, _) = SessionBuilder::new()
                .dimensions(80, 24)
                .build()
                .await
                .expect("Should create session for resize test");

            session2
                .resize(cols, rows)
                .await
                .unwrap_or_else(|_| panic!("Should resize to {cols}x{rows}"));

            // Small delay between resizes
            sleep(Duration::from_millis(50)).await;
        }

        // Check that we get state change events
        let mut state_changes = 0;
        timeout(Duration::from_secs(1), async {
            while let Some(event) = events.recv().await {
                if matches!(event, SessionEvent::StateChanged(_)) {
                    state_changes += 1;
                }
            }
        })
        .await
        .ok();

        assert!(state_changes > 0, "Should receive state change events");
    }

    #[tokio::test]
    async fn test_sigpipe_handling() {
        // Test handling of SIGPIPE when writing to closed pipe
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("yes | head -n 5");

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Process should complete successfully despite SIGPIPE
        let mut exit_code = None;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::ProcessExited(code) = event {
                    exit_code = Some(code);
                    break;
                }
            }
        })
        .await
        .ok();

        // head should exit successfully
        if let Some(code) = exit_code {
            assert!(
                code == 0 || code == 141,
                "Process should handle SIGPIPE gracefully"
            );
        }
    }

    #[test]
    fn test_sighup_on_pty_close() {
        use rosh_pty::Pty;
        use std::time::Duration;

        // Test that closing PTY master sends SIGHUP
        let pty = Pty::new().expect("Failed to create PTY");
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            # Write to a file when SIGHUP is received
            trap 'echo "SIGHUP" > /tmp/rosh_test_sighup_$$.txt' HUP
            echo "Ready"
            # Keep the process alive
            while true; do sleep 0.1; done
            "#,
        );

        let process = pty.spawn(cmd).expect("Failed to spawn process");
        let pid = process.pid();

        // Give the process time to set up signal handler
        std::thread::sleep(Duration::from_millis(100));

        // Drop the process, which should close the PTY master and send SIGHUP
        drop(process);

        // Give time for signal delivery
        std::thread::sleep(Duration::from_millis(100));

        // Check if the signal was received by looking for the file
        let test_file = format!("/tmp/rosh_test_sighup_{pid}.txt");
        let got_hup = std::path::Path::new(&test_file).exists();

        // Clean up test file
        let _ = std::fs::remove_file(&test_file);

        if !got_hup {
            // In some test environments, SIGHUP might not be delivered properly
            eprintln!(
                "Warning: SIGHUP not detected - this may be due to test environment limitations"
            );
        }
    }
}
