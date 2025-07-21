fn main() -> anyhow::Result<()> {
    // Install default crypto provider for QUIC/TLS
    rosh_network::cert_validation::install_crypto_provider();

    // Call the sync entry point which will handle forking before creating tokio runtime
    rosh::server::main()
}
