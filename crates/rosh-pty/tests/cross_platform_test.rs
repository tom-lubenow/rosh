//! Cross-platform behavior tests

use rosh_pty::{Pty, SessionBuilder, SessionEvent};
use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;

#[cfg(unix)]
mod unix_tests {
    use super::*;

    #[tokio::test]
    async fn test_platform_shell_detection() {
        // Test default shell detection
        let (session, _events) = SessionBuilder::new()
            .build()
            .await
            .expect("Should create session with default shell");

        let state = session.get_state().await;
        assert!(
            state.width > 0 && state.height > 0,
            "Should have valid dimensions"
        );

        // Default shell should be from $SHELL or /bin/sh
        let expected_shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        println!("Using shell: {expected_shell}");
    }

    #[tokio::test]
    async fn test_macos_specific_behavior() {
        #[cfg(target_os = "macos")]
        {
            // Test macOS-specific commands
            let mut cmd = Command::new("sh");
            cmd.arg("-c")
                .arg("sw_vers -productVersion 2>/dev/null || echo 'Not macOS'");

            let (session, mut events) = SessionBuilder::new()
                .command(cmd)
                .build()
                .await
                .expect("Should create session");

            // Start session
            tokio::spawn(async move {
                let _ = session.start().await;
            });

            // Check for macOS version
            let mut is_macos = false;
            timeout(Duration::from_secs(2), async {
                while let Some(event) = events.recv().await {
                    if let SessionEvent::StateChanged(state) = event {
                        let output = String::from_utf8_lossy(&state.screen);
                        // macOS version format: XX.Y.Z
                        if output.contains(".") && !output.contains("Not macOS") {
                            is_macos = true;
                            println!("macOS version detected: {}", output.trim());
                            break;
                        }
                    }
                }
            })
            .await
            .ok();

            assert!(is_macos, "Should detect macOS version");
        }

        #[cfg(not(target_os = "macos"))]
        {
            println!("Skipping macOS-specific test on non-macOS platform");
        }
    }

    #[tokio::test]
    async fn test_linux_specific_behavior() {
        #[cfg(target_os = "linux")]
        {
            // Test Linux-specific features
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg("uname -o 2>/dev/null || uname -s");

            let (session, mut events) = SessionBuilder::new()
                .command(cmd)
                .build()
                .await
                .expect("Should create session");

            // Start session
            tokio::spawn(async move {
                let _ = session.start().await;
            });

            // Check for Linux
            let mut is_linux = false;
            timeout(Duration::from_secs(2), async {
                while let Some(event) = events.recv().await {
                    if let SessionEvent::StateChanged(state) = event {
                        let output = String::from_utf8_lossy(&state.screen);
                        if output.contains("Linux") || output.contains("GNU/Linux") {
                            is_linux = true;
                            println!("Linux system detected: {}", output.trim());
                            break;
                        }
                    }
                }
            })
            .await
            .ok();

            assert!(is_linux, "Should detect Linux system");
        }

        #[cfg(not(target_os = "linux"))]
        {
            println!("Skipping Linux-specific test on non-Linux platform");
        }
    }

    #[tokio::test]
    async fn test_terminal_type_handling() {
        // Test different TERM environment variable handling
        let term_types = vec!["xterm", "xterm-256color", "vt100", "dumb"];

        for term_type in term_types {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg("echo \"TERM=$TERM\"");

            let (session, mut events) = SessionBuilder::new()
                .command(cmd)
                .env("TERM", term_type)
                .build()
                .await
                .unwrap_or_else(|_| panic!("Should create session with TERM={term_type}"));

            // Start session
            tokio::spawn(async move {
                let _ = session.start().await;
            });

            // Check TERM output
            let mut got_term = false;
            timeout(Duration::from_secs(1), async {
                while let Some(event) = events.recv().await {
                    if let SessionEvent::StateChanged(state) = event {
                        let output = String::from_utf8_lossy(&state.screen);
                        if output.contains(&format!("TERM={term_type}")) {
                            got_term = true;
                            break;
                        }
                    }
                }
            })
            .await
            .ok();

            if !got_term {
                eprintln!("Warning: TERM={term_type} not detected in output");
            }
        }
    }

    #[tokio::test]
    async fn test_locale_handling() {
        // Test locale environment handling
        let locales = vec![
            ("C", "ASCII"),
            ("en_US.UTF-8", "UTF-8"),
            ("C.UTF-8", "UTF-8"),
        ];

        for (locale, _expected) in locales {
            let mut cmd = Command::new("sh");
            cmd.arg("-c")
                .arg("locale 2>/dev/null | grep LC_ALL || echo 'Locale not available'");

            let (session, mut events) = SessionBuilder::new()
                .command(cmd)
                .env("LC_ALL", locale)
                .build()
                .await
                .unwrap_or_else(|_| panic!("Should create session with locale={locale}"));

            // Start session
            tokio::spawn(async move {
                let _ = session.start().await;
            });

            // Check locale output
            timeout(Duration::from_secs(1), async {
                while let Some(event) = events.recv().await {
                    if let SessionEvent::StateChanged(state) = event {
                        let output = String::from_utf8_lossy(&state.screen);
                        println!("Locale {} output: {}", locale, output.trim());
                        break;
                    }
                }
            })
            .await
            .ok();
        }
    }

    #[tokio::test]
    async fn test_path_separator_handling() {
        // Test path handling across platforms
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(r#"echo "PATH has $(echo $PATH | tr ':' '\n' | wc -l) entries""#);

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Check PATH parsing
        let mut got_path_info = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("PATH has") && output.contains("entries") {
                        got_path_info = true;
                        println!("PATH info: {}", output.trim());
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(got_path_info, "Should parse PATH correctly");
    }

    #[test]
    fn test_pty_platform_constants() {
        // Test platform-specific constants
        use nix::pty::Winsize;

        let winsize = Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        // These should be valid on all Unix platforms
        assert_eq!(winsize.ws_row, 24);
        assert_eq!(winsize.ws_col, 80);

        // Test PTY allocation with specific size
        let mut pty = Pty::new().expect("Should create PTY");
        pty.resize(winsize.ws_col, winsize.ws_row)
            .expect("Should resize PTY");
    }

    #[tokio::test]
    async fn test_home_directory_expansion() {
        // Test home directory handling
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(r#"echo "HOME=$HOME" && cd ~ && pwd"#);

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Check home directory
        let mut got_home = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("HOME=") {
                        got_home = true;
                        // Home path format differs between platforms
                        if cfg!(target_os = "macos") {
                            assert!(
                                output.contains("/Users/") || output.contains("/home/"),
                                "Should have valid home path on macOS"
                            );
                        } else if cfg!(target_os = "linux") {
                            assert!(
                                output.contains("/home/") || output.contains("/root"),
                                "Should have valid home path on Linux"
                            );
                        }
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(got_home, "Should handle home directory");
    }

    #[tokio::test]
    async fn test_process_group_behavior() {
        // Test process group handling differences
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#"
            # Check if we're a process group leader
            if [ $$ -eq $(ps -o pgid= -p $$) ]; then
                echo "Process is group leader"
            else
                echo "Process is not group leader"
            fi
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

        // Check process group status
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("group leader") {
                        println!("Process group status: {}", output.trim());
                        break;
                    }
                }
            }
        })
        .await
        .ok();
    }

    #[tokio::test]
    async fn test_tty_device_naming() {
        // Test TTY device naming conventions
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("tty");

        let (session, mut events) = SessionBuilder::new()
            .command(cmd)
            .build()
            .await
            .expect("Should create session");

        // Start session
        tokio::spawn(async move {
            let _ = session.start().await;
        });

        // Check TTY device name
        let mut got_tty = false;
        timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let SessionEvent::StateChanged(state) = event {
                    let output = String::from_utf8_lossy(&state.screen);
                    if output.contains("/dev/") {
                        got_tty = true;
                        println!("TTY device: {}", output.trim());

                        // Platform-specific TTY naming
                        if cfg!(target_os = "macos") {
                            assert!(
                                output.contains("/dev/ttys") || output.contains("/dev/pty"),
                                "Should have macOS TTY naming"
                            );
                        } else if cfg!(target_os = "linux") {
                            assert!(
                                output.contains("/dev/pts/") || output.contains("/dev/pty"),
                                "Should have Linux TTY naming"
                            );
                        }
                        break;
                    }
                }
            }
        })
        .await
        .ok();

        assert!(got_tty, "Should detect TTY device");
    }
}
