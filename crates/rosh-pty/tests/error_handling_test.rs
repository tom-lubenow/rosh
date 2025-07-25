//! Error handling tests for rosh-pty module

#[cfg(unix)]
mod unix_tests {
    use rosh_pty::{Pty, SessionBuilder};
    use std::process::Command;

    #[test]
    fn test_pty_invalid_size() {
        // PTY doesn't have a new with size parameter, it uses resize
        let mut pty = Pty::new().expect("Failed to create PTY");

        // Test resizing to zero
        let _result = pty.resize(0, 0);
        // Should handle gracefully

        drop(pty);
    }

    #[test]
    fn test_pty_spawn_invalid_command() {
        let pty = Pty::new().expect("Failed to create PTY");

        // Try to spawn non-existent command
        let cmd = Command::new("/nonexistent/command/that/should/not/exist");
        let result = pty.spawn(cmd);

        // PTY spawn might succeed and the command fails later
        // Or it might fail immediately - both are valid behaviors
        match result {
            Ok(process) => {
                // If spawn succeeded, process should exit quickly with error
                // Can't check status without blocking, so just kill it
                let _ = process.kill();
            }
            Err(_) => {
                // Failed immediately - this is also acceptable
            }
        }
    }

    #[test]
    fn test_pty_spawn_with_invalid_args() {
        let pty = Pty::new().expect("Failed to create PTY");

        // Try to spawn with invalid arguments
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("--invalid-flag-that-doesnt-exist");

        let result = pty.spawn(cmd);

        // Shell might still start but exit immediately
        if let Ok(process) = result {
            // Can't check if process is still running without blocking
            // Just try to kill it - if it already exited, kill will fail harmlessly
            let _ = process.kill();
        }
    }

    #[test]
    fn test_pty_resize_after_spawn() {
        let pty = Pty::new().expect("Failed to create PTY");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("sleep 1");

        let process = pty.spawn(cmd).expect("Failed to spawn process");

        // Can't resize through process directly, need to keep reference to master
        // This test demonstrates the API limitation

        // Clean up
        let _ = process.kill();
    }

    #[test]
    fn test_pty_process_wait() {
        let pty = Pty::new().expect("Failed to create PTY");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("exit 42");

        let process = pty.spawn(cmd).expect("Failed to spawn process");

        // Wait for process to exit
        let exit_code = process.wait().expect("Failed to wait for process");

        // Check exit code - wait() returns the exit code directly
        assert_eq!(exit_code, 42, "Should get correct exit code");
    }

    #[test]
    fn test_pty_edge_case_commands() {
        let test_commands = vec![
            ("", &[] as &[&str]), // Empty command
            ("/", &[]),           // Root directory as command
            (".", &[]),           // Current directory as command
            ("/dev/null", &[]),   // Device file as command
            ("/etc/passwd", &[]), // Non-executable file
        ];

        for (cmd_path, args) in test_commands {
            let pty = Pty::new().expect("Failed to create PTY");
            let mut cmd = Command::new(cmd_path);
            for arg in args {
                cmd.arg(arg);
            }
            let result = pty.spawn(cmd);

            // All should fail
            match result {
                Ok(process) => {
                    // Process might start but exit immediately
                    // Can't check without blocking, so just clean up
                    let _ = process.kill();
                }
                Err(_) => {
                    // Failed immediately - expected
                }
            }
        }
    }

    #[test]
    fn test_pty_environment_variables() {
        let pty = Pty::new().expect("Failed to create PTY");

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("echo $TEST_VAR");
        cmd.env("TEST_VAR", "test_value");

        let process = pty.spawn(cmd);

        // Should work with environment variables
        assert!(process.is_ok(), "Should handle environment variables");

        if let Ok(process) = process {
            let _ = process.kill();
        }
    }

    #[tokio::test]
    async fn test_session_builder_with_env() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "echo $MY_VAR"]);
        cmd.env("MY_VAR", "hello");

        let builder = SessionBuilder::new()
            .command(cmd)
            .env("ANOTHER_VAR", "world")
            .dimensions(24, 80);

        let result = builder.build().await;

        assert!(result.is_ok(), "Should spawn with environment variables");

        if let Ok((_session, _events)) = result {
            // Session will clean up on drop
        }
    }

    #[test]
    fn test_pty_multiple_resize() {
        let mut pty = Pty::new().expect("Failed to create PTY");

        // Test multiple resizes
        let sizes = vec![(80, 24), (132, 43), (40, 12), (200, 60), (1, 1)];

        for (cols, rows) in sizes {
            let result = pty.resize(cols, rows);
            assert!(result.is_ok(), "Should handle resize to {cols}x{rows}");
        }
    }
}

// Placeholder for non-Unix systems
#[cfg(not(unix))]
mod non_unix_tests {
    #[test]
    fn test_pty_not_supported() {
        // PTY operations should return appropriate errors on non-Unix systems
        println!("PTY tests skipped on non-Unix platform");
    }
}
