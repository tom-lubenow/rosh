//! End-to-end tests for SSH integration
//!
//! These tests verify the complete SSH workflow from connection to data transfer.
//! They require SSH to be configured with localhost access.

use anyhow::Result;
use tokio::process::Command;

/// Check if SSH localhost access is available
async fn check_ssh_localhost() -> bool {
    let output = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=1",
            "localhost",
            "echo",
            "test",
        ])
        .output()
        .await
        .ok();

    matches!(output, Some(o) if o.status.success())
}

/// Helper to setup SSH key for testing if not already configured
#[allow(dead_code)]
async fn ensure_ssh_key() -> Result<()> {
    // Check if we can already SSH to localhost
    if check_ssh_localhost().await {
        return Ok(());
    }

    // Generate SSH key if it doesn't exist
    let ssh_dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?
        .join(".ssh");

    let key_path = ssh_dir.join("id_rsa_rosh_test");

    if !key_path.exists() {
        Command::new("ssh-keygen")
            .args([
                "-t",
                "rsa",
                "-b",
                "2048",
                "-f",
                key_path.to_str().unwrap(),
                "-N",
                "",
                "-C",
                "rosh-test-key",
            ])
            .status()
            .await?;
    }

    Ok(())
}
