use anyhow::Result;
use clap::Parser;
use tracing_subscriber;

#[derive(Parser, Debug)]
#[clap(name = "rosh", about = "Modern mobile shell - client")]
struct Args {
    /// Hostname or IP address to connect to
    target: String,
    
    /// Port number for the connection
    #[clap(short, long, default_value = "60001")]
    port: u16,
    
    /// Verbosity level
    #[clap(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(args.log_level)
        .init();
    
    tracing::info!("Starting Rosh client");
    tracing::info!("Connecting to {}:{}", args.target, args.port);
    
    // TODO: Implement client logic
    
    Ok(())
}