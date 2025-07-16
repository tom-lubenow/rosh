#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rosh::client::run().await
}
