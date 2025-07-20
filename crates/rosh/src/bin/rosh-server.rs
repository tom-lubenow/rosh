fn main() -> anyhow::Result<()> {
    // Call the sync entry point which will handle forking before creating tokio runtime
    rosh::server::main()
}
