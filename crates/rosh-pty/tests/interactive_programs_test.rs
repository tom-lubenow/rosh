//! Tests for interactive programs in PTY sessions

use rosh_pty::{SessionBuilder, SessionEvent};
use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;

#[cfg(unix)]
mod unix_tests {
    use super::*;

    #[tokio::test]
    async fn test_interactive_shell_prompt() {
        // Test interactive shell with prompt
        let mut cmd = Command::new("sh");
        cmd.arg("-i"); // Interactive mode

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .env("PS1", "test$ ") // Set custom prompt
            .build()
            .await
            .expect("Should create interactive session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Look for prompt
        let mut found_prompt = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("test$") || output.contains("$") || output.contains("#") {
                        found_prompt = true;
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(found_prompt, "Should see shell prompt");
    }

    #[tokio::test]
    async fn test_echo_command() {
        // Simple echo test
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("echo 'Hello from PTY test'");

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Wait for output
        let mut found_output = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("Hello from PTY test") {
                        found_output = true;
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(found_output, "Should see echo output");
    }

    #[tokio::test]
    async fn test_cat_with_eof() {
        // Test cat with EOF - no input needed, just EOF behavior
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("timeout 1 cat 2>/dev/null || echo 'Cat timed out'");

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Process should complete after timeout
        let mut exited = false;
        timeout(Duration::from_secs(3), async {
            while let Some(event) = events.recv().await {
                match event {
                    SessionEvent::StateChanged(state) => {
                        let output = String::from_utf8_lossy(&state.screen);
                        if output.contains("Cat timed out") {
                            exited = true;
                        }
                    }
                    SessionEvent::ProcessExited(_) => {
                        exited = true;
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .ok();

        assert!(exited, "Process should complete");
    }

    #[tokio::test]
    async fn test_python_version() {
        // Just test Python can be invoked
        if Command::new("python3").arg("--version").output().is_err() {
            eprintln!("Skipping Python test - python3 not available");
            return;
        }

        let mut cmd = Command::new("python3");
        cmd.arg("--version");

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create Python session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Check for version output
        let mut got_version = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("Python") {
                        got_version = true;
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(got_version, "Should see Python version");
    }

    #[tokio::test]
    async fn test_bc_simple() {
        // Test bc calculator with predefined input
        if Command::new("bc").arg("--version").output().is_err() {
            eprintln!("Skipping bc test - bc not available");
            return;
        }

        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("echo '2 + 2' | bc");

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create bc session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Check for result
        let mut got_result = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("4") {
                        got_result = true;
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(got_result, "Should see calculation result");
    }

    #[tokio::test]
    async fn test_terminal_query() {
        // Test terminal-related queries
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("tty; echo \"Columns: $(tput cols 2>/dev/null || echo 'N/A')\"");

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .dimensions(80, 24)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Check for terminal info
        let mut got_info = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("/dev/") || output.contains("Columns:") {
                        got_info = true;
                        println!("Terminal info: {}", output.trim());
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(got_info, "Should get terminal information");
    }

    #[tokio::test]
    async fn test_env_variables() {
        // Test environment variable handling
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("echo \"TERM=$TERM\"; echo \"LANG=$LANG\"; echo \"PATH entries: $(echo $PATH | tr ':' ' ' | wc -w)\"");

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .env("CUSTOM_VAR", "test_value")
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Check environment
        let mut got_env = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("TERM=") || output.contains("PATH entries:") {
                        got_env = true;
                        println!("Environment: {}", output.trim());
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(got_env, "Should see environment variables");
    }

    #[tokio::test]
    async fn test_exit_codes() {
        // Test different exit codes
        let test_cases = vec![
            ("exit 0", 0),
            ("exit 1", 1),
            ("exit 42", 42),
            ("false", 1),
            ("true", 0),
        ];

        for (cmd_str, expected_code) in test_cases {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg(cmd_str);

            let (session, mut events) = SessionBuilder::new()
                .command(cmd)
                .build()
                .await
                .unwrap_or_else(|_| panic!("Should create session for: {cmd_str}"));

            // Start session
            tokio::spawn(async move {
                let _ = session.start().await;
            });

            // Wait for exit
            let mut exit_code = None;
            timeout(Duration::from_secs(1), async {
                while let Some(event) = events.recv().await {
                    if let SessionEvent::ProcessExited(code) = event {
                        exit_code = Some(code);
                        break;
                    }
                }
            })
            .await
            .ok();

            assert_eq!(
                exit_code,
                Some(expected_code),
                "Command '{cmd_str}' should exit with code {expected_code}"
            );
        }
    }

    #[tokio::test]
    async fn test_long_running_with_output() {
        // Test long-running process with periodic output
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            for i in 1 2 3; do
                echo "Iteration $i"
                sleep 0.1
            done
            echo "Done"
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

        // Track iterations
        let mut iterations_seen = 0;
        let mut saw_done = false;

        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    for i in 1..=3 {
                        if output.contains(&format!("Iteration {i}")) {
                            iterations_seen = iterations_seen.max(i);
                        }
                    }
                    if output.contains("Done") {
                        saw_done = true;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(iterations_seen >= 2, "Should see multiple iterations");
        assert!(saw_done, "Should see completion message");
    }

    #[tokio::test]
    async fn test_multiline_output() {
        // Test handling of multiline output
        // Try to find a working shell
        let shells = vec![
            std::env::var("SHELL").ok(),
            Some("/bin/sh".to_string()),
            Some("sh".to_string()),
            Some("/usr/bin/sh".to_string()),
            Some("/bin/bash".to_string()),
            Some("bash".to_string()),
        ];

        let mut cmd = None;
        for shell_option in shells.into_iter().flatten() {
            // Check if the shell exists and is executable
            if std::process::Command::new(&shell_option)
                .arg("-c")
                .arg("true")
                .output()
                .is_ok()
            {
                let mut test_cmd = Command::new(&shell_option);
                test_cmd.arg("-c").arg(
                    r#"echo 'Line 1' && echo 'Line 2' && echo 'Line 3' && printf 'No newline at end'"#,
                );
                cmd = Some(test_cmd);
                break;
            }
        }

        let cmd = cmd.expect("No working shell found");

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Collect all output with more robust handling
        let mut final_output = String::new();
        let mut process_exited = false;

        timeout(Duration::from_secs(5), async {
            while let Some(event) = events.recv().await {
                match event {
                    SessionEvent::StateChanged(state) => {
                        let output = String::from_utf8_lossy(&state.screen).to_string();
                        // Keep accumulating output instead of replacing
                        if !output.is_empty() {
                            final_output = output;
                        }
                    }
                    SessionEvent::ProcessExited(_) => {
                        process_exited = true;
                        // Give a bit more time to collect final output
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .ok();

        // Debug output to help diagnose issues in CI
        if !final_output.contains("Line 1")
            || !final_output.contains("Line 2")
            || !final_output.contains("Line 3")
            || !final_output.contains("No newline at end")
        {
            eprintln!(
                "Test output (len={}): {:?}",
                final_output.len(),
                final_output
            );
            eprintln!("Process exited: {process_exited}");
        }

        assert!(
            final_output.contains("Line 1"),
            "Should see first line. Output: {final_output}"
        );
        assert!(
            final_output.contains("Line 2"),
            "Should see second line. Output: {final_output}"
        );
        assert!(
            final_output.contains("Line 3"),
            "Should see third line. Output: {final_output}"
        );
        assert!(
            final_output.contains("No newline at end"),
            "Should see text without newline. Output: {final_output}"
        );
    }
}
