#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Run the client and ensure proper terminal cleanup on exit
    let result = rosh::client::run().await;

    // Ensure terminal is in a good state before exiting
    // This helps prevent terminal corruption when errors are printed
    use std::io::{self, Write};
    let _ = io::stderr().flush();
    let _ = io::stdout().flush();

    result
}
