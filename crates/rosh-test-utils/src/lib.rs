pub mod fixtures;
pub mod harness;
pub mod network;
pub mod terminal;

pub use harness::{ClientHandle, PtyClientHandle, ServerHandle, TestHarness};
pub use network::{NetworkConditions, NetworkSimulator};
pub use terminal::{TerminalCapture, TerminalComparator};

use std::sync::Once;
use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

pub fn init_test_logging() {
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("rosh=debug,rosh_test_utils=debug")),
            )
            .with_test_writer()
            .init();
    });
}

#[derive(Debug, Clone)]
pub struct TestConfig {
    pub server_port: Option<u16>,
    pub client_timeout: std::time::Duration,
    pub server_timeout: std::time::Duration,
    pub capture_output: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            server_port: None, // Use random port
            client_timeout: std::time::Duration::from_secs(30),
            server_timeout: std::time::Duration::from_secs(30),
            capture_output: true,
        }
    }
}
