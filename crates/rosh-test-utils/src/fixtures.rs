use anyhow::Result;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub struct TestFixtures {
    temp_dir: TempDir,
}

impl TestFixtures {
    pub fn new() -> Result<Self> {
        Ok(Self {
            temp_dir: TempDir::new()?,
        })
    }

    pub fn create_test_script(&self, name: &str, content: &str) -> Result<PathBuf> {
        let script_path = self.temp_dir.path().join(name);
        std::fs::write(&script_path, content)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms)?;
        }

        Ok(script_path)
    }

    pub fn create_test_file(&self, name: &str, content: &[u8]) -> Result<PathBuf> {
        let file_path = self.temp_dir.path().join(name);
        std::fs::write(&file_path, content)?;
        Ok(file_path)
    }

    pub fn create_test_keys(&self) -> Result<(PathBuf, PathBuf)> {
        let private_key = self.temp_dir.path().join("test_key");
        let public_key = self.temp_dir.path().join("test_key.pub");

        // Generate test SSH keys using ssh-keygen
        std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                private_key.to_str().unwrap(),
                "-N",
                "", // No passphrase
                "-C",
                "test@rosh",
            ])
            .output()?;

        Ok((private_key, public_key))
    }

    pub fn path(&self) -> &Path {
        self.temp_dir.path()
    }
}

// Common test data
pub mod data {
    pub const HELLO_WORLD: &str = "Hello, World!\n";

    pub const UNICODE_TEST: &str = "🦀 Rust 日本語 العربية\n";

    pub const ANSI_COLORS: &str = "\x1b[31mRed\x1b[0m \x1b[32mGreen\x1b[0m \x1b[34mBlue\x1b[0m\n";

    pub const LARGE_TEXT: &str = include_str!("fixtures/large_text.txt");

    pub fn generate_random_data(size: usize) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..size).map(|_| rng.gen()).collect()
    }

    pub fn generate_text_lines(count: usize) -> String {
        (0..count)
            .map(|i| format!("Line {i}: The quick brown fox jumps over the lazy dog"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
