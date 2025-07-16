use anyhow::Result;
use clap::Parser;
use tracing_subscriber;

#[derive(Parser, Debug)]
#[clap(name = "rosh-server", about = "Modern mobile shell - server")]
struct Args {
    /// Port to listen on
    #[clap(short, long, default_value = "60001")]
    port: u16,
    
    /// Address to bind to
    #[clap(short, long, default_value = "0.0.0.0")]
    bind: String,
    
    /// Verbosity level
    #[clap(short, long, default_value = "info")]
    log_level: String,
    
    /// Shell to execute
    #[clap(short, long)]
    shell: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(args.log_level)
        .init();
    
    tracing::info!("Starting Rosh server");
    tracing::info!("Listening on {}:{}", args.bind, args.port);
    
    // TODO: Implement server logic
    
    Ok(())
}