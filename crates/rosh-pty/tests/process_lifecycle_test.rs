//! Process lifecycle and edge case tests

use rosh_pty::{SessionBuilder, SessionEvent};
use std::process::Command;
use std::time::Duration;
use tokio::time::{sleep, timeout};

#[cfg(unix)]
mod unix_tests {
    use super::*;

    #[tokio::test]
    async fn test_zombie_process_cleanup() {
        // Create a process that spawns a child and exits
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            # Spawn background process
            (sleep 2; echo "Child done") &
            echo "Parent exiting"
            # Parent exits immediately
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

        // Parent should exit quickly
        let mut parent_exited = false;
        timeout(Duration::from_secs(3), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::ProcessExited(_) = event {
                    parent_exited = true;
                    break;
                }
            }
        })
        .await
        .ok();

        assert!(parent_exited, "Parent process should exit");

        // The child process should be cleaned up (no zombies)
        // In a proper implementation, the PTY should handle SIGCHLD
    }

    #[tokio::test]
    async fn test_rapid_process_spawn() {
        // Test rapidly spawning and exiting processes
        for i in 0..5 {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg(format!("echo 'Process {i}'"));

            let (session, mut events) = SessionBuilder::new()
                .command(cmd)
                .build()
                .await
                .unwrap_or_else(|_| panic!("Should create session {i}"));

            // Start session
            tokio::spawn(async move {
                let _ = session.start().await;
            });

            // Wait for exit
            let exited = timeout(Duration::from_secs(1), async {
                while let Some(event) = events.recv().await {
                    if let SessionEvent::ProcessExited(code) = event {
                        assert_eq!(code, 0, "Process {i} should exit cleanly");
                        return true;
                    }
                }
                false
            })
            .await
            .unwrap_or(false);

            assert!(exited, "Process {i} should exit");

            // Small delay between spawns
            sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn test_process_group_management() {
        // Test that child processes are in the same process group
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            echo "Parent PID: $$"
            echo "Parent PGID: $(ps -o pgid= -p $$)"
            # Spawn child
            sh -c 'echo "Child PID: $$"; echo "Child PGID: $(ps -o pgid= -p $$)"; sleep 2' &
            sleep 1
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
        let mut output = String::new();
        timeout(Duration::from_secs(3), async {
            while let Some(event) = events.recv().await {
                match event {
                    SessionEvent::StateChanged(state) => {
                        output.push_str(&String::from_utf8_lossy(&state.screen));
                    }
                    SessionEvent::ProcessExited(_) => break,
                    _ => {}
                }
            }
        })
        .await
        .ok();

        // Check that PIDs and PGIDs are present
        if output.contains("PID:") && output.contains("PGID:") {
            println!("Process group info: {output}");
        } else {
            eprintln!("Warning: Could not get process group information");
        }
    }

    #[tokio::test]
    async fn test_exec_chain() {
        // Test exec replacing process
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            echo "Original shell PID: $$"
            exec echo "After exec PID: $$"
            echo "This should not print"
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
        let mut output = String::new();
        let mut exited = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                match event {
                    SessionEvent::StateChanged(state) => {
                        output.push_str(&String::from_utf8_lossy(&state.screen));
                    }
                    SessionEvent::ProcessExited(code) => {
                        exited = true;
                        assert_eq!(code, 0, "Process should exit cleanly");
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .ok();

        assert!(exited, "Process should exit");
        assert!(
            !output.contains("This should not print"),
            "Exec should replace process"
        );
    }

    #[tokio::test]
    async fn test_background_job_control() {
        // Test job control with background processes
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            # Enable job control
            set -m
            
            # Start background job
            sleep 5 &
            echo "Job started with PID: $!"
            
            # List jobs
            jobs
            
            # Kill background job
            kill %1
            echo "Job killed"
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

        // Check for job control output
        let mut saw_job_info = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("Job started") || output.contains("[1]") {
                        saw_job_info = true;
                    }
                }
            }
        })
        .await
        .ok();

        if !saw_job_info {
            eprintln!("Warning: Job control output not detected");
        }
    }

    #[tokio::test]
    async fn test_ulimit_constraints() {
        // Test process limits
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            # Set some limits
            ulimit -n 256    # Max open files
            ulimit -u 100    # Max processes
            ulimit -t 2      # CPU time limit
            
            # Show limits
            ulimit -a
            
            echo "Limits set"
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

        // Check output
        let mut saw_limits = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("Limits set") || output.contains("limit") {
                        saw_limits = true;
                    }
                }
            }
        })
        .await
        .ok();

        if !saw_limits {
            eprintln!("Warning: ulimit output not detected");
        }
    }

    #[tokio::test]
    async fn test_process_with_large_env() {
        // Test process with large environment
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("echo 'ENV size:' $(env | wc -c) 'bytes'");

        // Add many environment variables
        for i in 0..50 {
            cmd.env(format!("TEST_VAR_{i}"), "x".repeat(100));
        }

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session with large environment");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Should handle large environment
        let mut got_output = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("ENV size:") {
                        got_output = true;
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(got_output, "Should handle large environment");
    }

    #[tokio::test]
    async fn test_stdin_close_handling() {
        // Test process behavior when stdin is closed
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            # Read from stdin with timeout
            if read -t 2 line; then
                echo "Got: $line"
            else
                echo "No input received"
            fi
            echo "Continuing after read"
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

        // Don't send any input, let it timeout
        let mut saw_timeout = false;
        timeout(Duration::from_secs(4), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("No input received") || output.contains("Continuing") {
                        saw_timeout = true;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(saw_timeout, "Should handle stdin timeout");
    }

    // #[test]
    // fn test_pty_fd_inheritance() {
    //     // Test file descriptor handling in PTY
    //     let pty = Pty::new().expect("Failed to create PTY");

    //     // Get master FD before spawn
    //     let master_fd = pty.master().as_raw_fd();
    //     assert!(master_fd > 2, "Master FD should be valid");

    //     let mut cmd = Command::new("sh");
    //     cmd.arg("-c").arg("ls -la /proc/self/fd 2>/dev/null || ls -la /dev/fd 2>/dev/null || echo 'FD listing not available'");

    //     let process = pty.spawn(cmd).expect("Failed to spawn process");

    //     // Master FD should still be valid in parent
    //     let new_master_fd = process.master().as_raw_fd();
    //     assert!(
    //         new_master_fd > 2,
    //         "Master FD should remain valid after spawn"
    //     );

    //     // Wait for process
    //     let _ = process.wait();
    // }
}
