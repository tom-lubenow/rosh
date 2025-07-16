#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rosh::server::run().await
}
