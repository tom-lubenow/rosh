//! Bootstrap module for establishing Rosh connections via SSH
//!
//! This module implements the same IP resolution strategies as mosh:
//! - local: Resolve hostname locally before SSH connection
//! - remote: Use SSH_CONNECTION environment variable from server
//! - proxy: Use SSH ProxyCommand (default)

use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{debug, info};

use rosh_crypto::CipherAlgorithm;
use rosh_state::CompressionAlgorithm;

/// IP resolution strategy for SSH connections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteIpStrategy {
    /// Resolve hostname locally before SSH connection
    Local,
    /// Get IP from SSH_CONNECTION on remote server
    Remote,
    /// Use SSH ProxyCommand (default)
    Proxy,
}

impl RemoteIpStrategy {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "remote" => Ok(Self::Remote),
            "proxy" => Ok(Self::Proxy),
            _ => anyhow::bail!("Unknown remote IP strategy: {}", s),
        }
    }
}

/// Connection parameters for establishing a Rosh connection
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BootstrapConnectParams {
    /// Server IP address
    pub ip: String,
    /// Server port (QUIC/Rosh port, not SSH port)
    pub port: u16,
    /// Session key (base64 encoded)
    pub session_key: String,
    /// Log file path (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
    /// Client address (from SSH_CONNECTION)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_addr: Option<String>,
}

/// Options for bootstrapping a connection via SSH
pub struct BootstrapOptions<'a> {
    /// User (if specified)
    pub user: Option<&'a str>,
    /// Hostname
    pub host: &'a str,
    /// SSH port (None means use SSH config)
    pub ssh_port: Option<u16>,
    /// Remote command to start server
    pub remote_command: &'a str,
    /// Path to rosh-server binary on remote
    pub rosh_server_bin: Option<&'a str>,
    /// Additional SSH options
    pub ssh_options: &'a [String],
    /// Cipher algorithm
    pub cipher: CipherAlgorithm,
    /// Compression algorithm
    pub compression: Option<CompressionAlgorithm>,
    /// IP resolution strategy
    pub remote_ip_strategy: RemoteIpStrategy,
    /// Network family preference
    pub family: NetworkFamily,
}

/// Network family preference
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkFamily {
    /// IPv4 only
    Inet,
    /// IPv6 only
    Inet6,
    /// Try all types
    All,
    /// Prefer IPv4 (default)
    PreferInet,
    /// Prefer IPv6
    PreferInet6,
}

impl NetworkFamily {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "inet" | "ipv4" | "4" => Ok(Self::Inet),
            "inet6" | "ipv6" | "6" => Ok(Self::Inet6),
            "all" => Ok(Self::All),
            "prefer-inet" | "prefer-ipv4" => Ok(Self::PreferInet),
            "prefer-inet6" | "prefer-ipv6" => Ok(Self::PreferInet6),
            _ => anyhow::bail!("Unknown network family: {}", s),
        }
    }
}

/// Client-side bootstrap functionality
pub mod client {
    use super::*;

    /// Bootstrap a Rosh connection via SSH
    pub async fn bootstrap_via_ssh(
        options: BootstrapOptions<'_>,
    ) -> Result<BootstrapConnectParams> {
        info!(
            "Starting SSH bootstrap to {} using {} IP resolution strategy",
            options.host,
            match options.remote_ip_strategy {
                RemoteIpStrategy::Local => "local",
                RemoteIpStrategy::Remote => "remote",
                RemoteIpStrategy::Proxy => "proxy",
            }
        );

        match options.remote_ip_strategy {
            RemoteIpStrategy::Local => bootstrap_local_resolution(options).await,
            RemoteIpStrategy::Remote => bootstrap_remote_resolution(options).await,
            RemoteIpStrategy::Proxy => bootstrap_proxy_resolution(options).await,
        }
    }

    /// Local resolution strategy - resolve hostname before SSH
    async fn bootstrap_local_resolution(
        options: BootstrapOptions<'_>,
    ) -> Result<BootstrapConnectParams> {
        info!("Using local IP resolution for {}", options.host);

        // Resolve hostname locally
        let ip = resolve_hostname(options.host, options.family).await?;

        // Build SSH target with resolved IP
        let ssh_target = if let Some(user) = options.user {
            format!("{user}@{ip}")
        } else {
            ip.to_string()
        };

        // Start server via SSH using resolved IP
        info!("Starting Rosh server via SSH on resolved IP: {}", ip);
        let (port, session_key) = start_server_ssh(&ssh_target, &options).await?;
        info!("Server started on port {} with session key", port);

        Ok(BootstrapConnectParams {
            ip: ip.to_string(),
            port,
            session_key,
            log_file: None,
            client_addr: None,
        })
    }

    /// Remote resolution strategy - get IP from SSH_CONNECTION
    async fn bootstrap_remote_resolution(
        options: BootstrapOptions<'_>,
    ) -> Result<BootstrapConnectParams> {
        info!("Using remote IP resolution for {}", options.host);

        // Build SSH target
        let ssh_target = if let Some(user) = options.user {
            format!("{}@{}", user, options.host)
        } else {
            options.host.to_string()
        };

        // Start server via SSH with SSH_CONNECTION capture
        info!("Starting Rosh server via SSH and capturing SSH_CONNECTION");
        let params = start_server_ssh_with_connection(&ssh_target, &options).await?;
        info!(
            "Server started on {}:{} with session key",
            params.ip, params.port
        );
        if let Some(ref log_path) = params.log_file {
            info!("Server log file: {}", log_path);
        }

        Ok(params)
    }

    /// Proxy resolution strategy - use SSH ProxyCommand
    async fn bootstrap_proxy_resolution(
        options: BootstrapOptions<'_>,
    ) -> Result<BootstrapConnectParams> {
        info!("Using proxy IP resolution for {}", options.host);

        // Build SSH target
        let ssh_target = if let Some(user) = options.user {
            format!("{}@{}", user, options.host)
        } else {
            options.host.to_string()
        };

        // Start server via SSH with proxy command
        info!("Starting Rosh server via SSH with ProxyCommand");
        let params = start_server_ssh_with_proxy(&ssh_target, &options).await?;
        info!(
            "Server started on {}:{} with session key",
            params.ip, params.port
        );
        if let Some(ref log_path) = params.log_file {
            info!("Server log file: {}", log_path);
        }

        Ok(params)
    }

    /// Resolve hostname to IP address with family preference
    async fn resolve_hostname(host: &str, family: NetworkFamily) -> Result<IpAddr> {
        let addr_str = format!("{host}:0"); // Add dummy port for resolution
        let addrs: Vec<SocketAddr> = addr_str
            .to_socket_addrs()
            .with_context(|| format!("Failed to resolve {host}"))?
            .collect();

        if addrs.is_empty() {
            anyhow::bail!("No addresses found for {}", host);
        }

        // Filter and sort based on family preference
        let ip = match family {
            NetworkFamily::Inet => addrs
                .iter()
                .find(|addr| addr.is_ipv4())
                .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for {}", host))?
                .ip(),
            NetworkFamily::Inet6 => addrs
                .iter()
                .find(|addr| addr.is_ipv6())
                .ok_or_else(|| anyhow::anyhow!("No IPv6 address found for {}", host))?
                .ip(),
            NetworkFamily::PreferInet => addrs
                .iter()
                .find(|addr| addr.is_ipv4())
                .or_else(|| addrs.first())
                .ok_or_else(|| anyhow::anyhow!("No addresses found for {}", host))?
                .ip(),
            NetworkFamily::PreferInet6 => addrs
                .iter()
                .find(|addr| addr.is_ipv6())
                .or_else(|| addrs.first())
                .ok_or_else(|| anyhow::anyhow!("No addresses found for {}", host))?
                .ip(),
            NetworkFamily::All => addrs
                .first()
                .ok_or_else(|| anyhow::anyhow!("No addresses found for {}", host))?
                .ip(),
        };

        Ok(ip)
    }

    /// Start server via SSH and return port and session key
    async fn start_server_ssh(
        ssh_target: &str,
        options: &BootstrapOptions<'_>,
    ) -> Result<(u16, String)> {
        let mut ssh_cmd = build_ssh_command(ssh_target, options, false);

        // Build remote command
        let remote_cmd = build_remote_command(options);
        ssh_cmd.arg(remote_cmd);

        // Execute and parse output
        let output = execute_ssh_command(ssh_cmd).await?;
        let params = parse_server_output(&output)?;
        Ok((params.port, params.session_key))
    }

    /// Start server via SSH with SSH_CONNECTION capture
    async fn start_server_ssh_with_connection(
        ssh_target: &str,
        options: &BootstrapOptions<'_>,
    ) -> Result<BootstrapConnectParams> {
        let mut ssh_cmd = build_ssh_command(ssh_target, options, true);

        // Build remote command with SSH_CONNECTION capture
        let remote_cmd = build_remote_command(options);
        let full_cmd = format!(
            r#"sh -c '[ -n "$SSH_CONNECTION" ] && printf "\nROSH SSH_CONNECTION %s\n" "$SSH_CONNECTION" ; {remote_cmd}'"#
        );
        ssh_cmd.arg(full_cmd);

        // Execute and parse output
        let output = execute_ssh_command(ssh_cmd).await?;
        parse_server_output(&output)
    }

    /// Start server via SSH with ProxyCommand
    async fn start_server_ssh_with_proxy(
        ssh_target: &str,
        options: &BootstrapOptions<'_>,
    ) -> Result<BootstrapConnectParams> {
        // Get the path to the rosh binary
        let rosh_binary =
            std::env::current_exe().context("Failed to get current executable path")?;

        // Build the ProxyCommand
        let proxy_cmd = format!(
            "{} --family={} --fake-proxy -- %h %p",
            rosh_binary.display(),
            match options.family {
                NetworkFamily::Inet => "inet",
                NetworkFamily::Inet6 => "inet6",
                NetworkFamily::PreferInet => "prefer-inet",
                NetworkFamily::PreferInet6 => "prefer-inet6",
                NetworkFamily::All => "all",
            }
        );

        let mut ssh_cmd = Command::new("ssh");

        // Basic SSH options
        ssh_cmd.arg("-n"); // No stdin
        ssh_cmd.arg("-T"); // No PTY allocation

        // Add ProxyCommand
        ssh_cmd.arg("-o").arg(format!("ProxyCommand={proxy_cmd}"));
        ssh_cmd.arg("-o").arg("ControlMaster=no");
        ssh_cmd.arg("-o").arg("ControlPath=none");

        // Add port if specified
        if let Some(port) = options.ssh_port {
            ssh_cmd.arg("-p").arg(port.to_string());
        }

        // Add custom SSH options
        for opt in options.ssh_options {
            ssh_cmd.arg("-o").arg(opt);
        }

        // Add target
        ssh_cmd.arg(ssh_target);
        ssh_cmd.arg("--");

        // Set up process
        ssh_cmd.stdout(Stdio::piped());
        ssh_cmd.stderr(Stdio::piped());

        // Build remote command
        let remote_cmd = build_remote_command(options);
        ssh_cmd.arg(remote_cmd);

        // Execute and collect output
        debug!("Executing SSH command with ProxyCommand");
        let mut child = ssh_cmd.spawn().context("Failed to spawn SSH process")?;

        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get stderr from SSH"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get stdout from SSH"))?;

        let mut stderr_reader = BufReader::new(stderr);
        let mut stdout_reader = BufReader::new(stdout);
        let mut output = String::new();
        let mut resolved_ip = None;

        let timeout = Duration::from_secs(10);
        let start = std::time::Instant::now();

        // Read stderr for ROSH IP line
        let mut stderr_line = String::new();
        while start.elapsed() < timeout {
            match tokio::time::timeout(
                Duration::from_millis(100),
                stderr_reader.read_line(&mut stderr_line),
            )
            .await
            {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(_)) => {
                    if stderr_line.starts_with("ROSH IP ") {
                        let ip_str = stderr_line.trim_start_matches("ROSH IP ").trim();
                        resolved_ip =
                            Some(ip_str.parse::<IpAddr>().with_context(|| {
                                format!("Failed to parse IP from proxy: {ip_str}")
                            })?);
                        debug!("Proxy resolved IP: {:?}", resolved_ip);
                    }
                    stderr_line.clear();
                }
                Ok(Err(e)) => debug!("Error reading stderr: {}", e),
                Err(_) => continue,
            }
        }

        // Read stdout for server output
        while start.elapsed() < timeout {
            let mut line = String::new();
            match tokio::time::timeout(
                Duration::from_millis(100),
                stdout_reader.read_line(&mut line),
            )
            .await
            {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(_)) => {
                    output.push_str(&line);
                    // Check if we have all required output
                    if output.contains("ROSH CONNECT ") {
                        // Give a brief moment for any remaining output
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        // Read any remaining lines without blocking
                        while let Ok(Ok(n)) = tokio::time::timeout(
                            Duration::from_millis(10),
                            stdout_reader.read_line(&mut line),
                        )
                        .await
                        {
                            if n == 0 {
                                break;
                            }
                            output.push_str(&line);
                            line.clear();
                        }
                        break;
                    }
                }
                Ok(Err(e)) => return Err(e).context("Failed to read SSH output"),
                Err(_) => continue,
            }
        }

        // Wait for SSH process to exit naturally (like mosh)
        // The server detached, so SSH should exit on its own
        let _ = child.wait().await;

        if output.is_empty() {
            anyhow::bail!("SSH command produced no output");
        }

        // Parse server output
        let mut params = parse_server_output(&output)?;

        // Use the IP resolved by the proxy if available
        if let Some(ip) = resolved_ip {
            debug!("Using proxy-resolved IP: {}", ip);
            params.ip = ip.to_string();
        }

        Ok(params)
    }

    /// Build SSH command with appropriate options
    fn build_ssh_command(
        ssh_target: &str,
        options: &BootstrapOptions<'_>,
        needs_family_hint: bool,
    ) -> Command {
        let mut cmd = Command::new("ssh");

        // Basic SSH options (like mosh)
        cmd.arg("-n"); // No stdin

        // Only set port if explicitly specified
        // This allows SSH config to take precedence for hosts defined there
        if let Some(port) = options.ssh_port {
            cmd.arg("-p").arg(port.to_string());
        }

        cmd.arg("-o").arg("ControlMaster=no");
        cmd.arg("-o").arg("ControlPath=none");

        // Add family hints if needed (for remote strategy)
        if needs_family_hint {
            match options.family {
                NetworkFamily::Inet => {
                    cmd.arg("-4");
                }
                NetworkFamily::Inet6 => {
                    cmd.arg("-6");
                }
                _ => {}
            }
        }

        // Add custom SSH options
        for opt in options.ssh_options {
            cmd.arg("-o").arg(opt);
        }

        // Add target
        cmd.arg(ssh_target);
        cmd.arg("--");

        // Set up process
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        cmd
    }

    /// Build remote server command
    fn build_remote_command(options: &BootstrapOptions<'_>) -> String {
        let server_cmd = options.rosh_server_bin.unwrap_or(options.remote_command);
        let mut args = vec![
            server_cmd.to_string(),
            "--bind".to_string(),
            "0.0.0.0:0".to_string(),
            "--one-shot".to_string(),
            "--timeout".to_string(),
            "60".to_string(),
            "--detach".to_string(), // Properly detach as daemon after printing params
        ];

        // Add cipher option
        match options.cipher {
            CipherAlgorithm::Aes128Gcm => {
                args.extend(["--cipher".to_string(), "aes-gcm".to_string()])
            }
            CipherAlgorithm::Aes256Gcm => {
                args.extend(["--cipher".to_string(), "aes-256-gcm".to_string()])
            }
            CipherAlgorithm::ChaCha20Poly1305 => {
                args.extend(["--cipher".to_string(), "chacha20-poly1305".to_string()])
            }
        }

        // Add compression option
        if let Some(comp) = options.compression {
            match comp {
                CompressionAlgorithm::Zstd => {
                    args.extend(["--compression".to_string(), "zstd".to_string()])
                }
                CompressionAlgorithm::Lz4 => {
                    args.extend(["--compression".to_string(), "lz4".to_string()])
                }
            }
        }

        args.join(" ")
    }

    /// Execute SSH command and collect output
    async fn execute_ssh_command(mut cmd: Command) -> Result<String> {
        debug!("Executing SSH command to start remote server");
        let mut child = cmd.spawn().context("Failed to spawn SSH process")?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get stdout from SSH"))?;

        let mut stdout_reader = BufReader::new(stdout);
        let mut output = String::new();

        let timeout = Duration::from_secs(10);
        let start = std::time::Instant::now();

        // Read until we get the required output or timeout
        while start.elapsed() < timeout {
            let mut line = String::new();
            match tokio::time::timeout(
                Duration::from_millis(100),
                stdout_reader.read_line(&mut line),
            )
            .await
            {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(_)) => {
                    output.push_str(&line);
                    // Check if we have all required output
                    if output.contains("ROSH CONNECT ") {
                        // Give a brief moment for any remaining output
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        // Read any remaining lines without blocking
                        while let Ok(Ok(n)) = tokio::time::timeout(
                            Duration::from_millis(10),
                            stdout_reader.read_line(&mut line),
                        )
                        .await
                        {
                            if n == 0 {
                                break;
                            }
                            output.push_str(&line);
                            line.clear();
                        }
                        break;
                    }
                }
                Ok(Err(e)) => return Err(e).context("Failed to read SSH output"),
                Err(_) => continue, // Timeout on read, continue
            }
        }

        // Wait for SSH process to exit naturally (like mosh)
        // The server detached, so SSH should exit on its own
        let _ = child.wait().await;

        if output.is_empty() {
            anyhow::bail!("SSH command produced no output");
        }

        Ok(output)
    }

    /// Parse server output for connection parameters
    fn parse_server_output(output: &str) -> Result<BootstrapConnectParams> {
        debug!("Parsing server output for connection parameters");

        // First look for log file path
        let mut log_file = None;
        for line in output.lines() {
            let line = line.trim();
            if line.starts_with("SERVER_LOG_FILE: ") {
                log_file = Some(line.strip_prefix("SERVER_LOG_FILE: ").unwrap().to_string());
                debug!("Found log file: {:?}", log_file);
                break;
            }
        }

        // Look for the JSON connection params
        for line in output.lines() {
            let line = line.trim();
            if line.starts_with("ROSH CONNECT ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let port: u16 = parts[2]
                        .parse()
                        .with_context(|| format!("Failed to parse port: {}", parts[2]))?;
                    let session_key = parts[3].to_string();

                    debug!(
                        "Found connection params: port={}, key={}",
                        port, session_key
                    );

                    let params = BootstrapConnectParams {
                        ip: String::new(), // Will be filled in by caller
                        port,
                        session_key,
                        log_file,
                        client_addr: None,
                    };

                    return Ok(params);
                } else {
                    anyhow::bail!("Invalid ROSH CONNECT format: {}", line);
                }
            }
        }

        anyhow::bail!(
            "Server did not provide connection parameters. Output was:\n{}",
            output.lines().take(20).collect::<Vec<_>>().join("\n")
        )
    }
}

/// Server-side bootstrap functionality
pub mod server {
    use super::*;
    use std::io::Write;
    use std::net::UdpSocket;
    use std::path::PathBuf;

    /// Detach from parent process without communicating params
    /// This is called AFTER params have already been printed to stdout
    /// Uses single fork like mosh-server
    pub fn detach_without_params() -> Result<()> {
        #[cfg(unix)]
        {
            // Flush all output before forking
            std::io::stdout().flush()?;
            std::io::stderr().flush()?;

            // Single fork like mosh
            match unsafe { libc::fork() } {
                -1 => anyhow::bail!("Failed to fork: {}", std::io::Error::last_os_error()),
                0 => {
                    // Child process - continue execution
                    Ok(())
                }
                pid => {
                    // Parent process
                    eprintln!("[rosh-server detached, pid = {pid}]");
                    std::io::stderr().flush()?;

                    // Drain terminal output if attached to tty (like mosh)
                    if unsafe { libc::isatty(1) } == 1 {
                        unsafe {
                            libc::tcdrain(1);
                        }
                    }
                    if unsafe { libc::isatty(2) } == 1 {
                        unsafe {
                            libc::tcdrain(2);
                        }
                    }

                    // Parent exits
                    std::process::exit(0);
                }
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix platforms, just continue
            Ok(())
        }
    }

    /// Properly detach from parent process using double-fork and pipe communication
    pub fn detach_and_communicate(params: &BootstrapConnectParams) -> Result<()> {
        #[cfg(unix)]
        {
            use std::io::Read;
            use std::os::unix::io::FromRawFd;

            // Create pipe for communication
            let mut fds = [0; 2];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
                anyhow::bail!("Failed to create pipe: {}", std::io::Error::last_os_error());
            }
            let (read_fd, write_fd) = (fds[0], fds[1]);

            match unsafe { libc::fork() } {
                -1 => anyhow::bail!("Failed to fork: {}", std::io::Error::last_os_error()),
                0 => {
                    // Child process
                    unsafe {
                        libc::close(read_fd);
                    }

                    // Write connection params to parent through pipe
                    let json = serde_json::to_string(params)?;
                    let mut write_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
                    write_file.write_all(json.as_bytes())?;
                    write_file.flush()?;
                    std::mem::forget(write_file); // Don't close the fd twice
                    unsafe {
                        libc::close(write_fd);
                    }

                    // Create new session
                    if unsafe { libc::setsid() } == -1 {
                        eprintln!(
                            "Failed to create new session: {}",
                            std::io::Error::last_os_error()
                        );
                        std::process::exit(1);
                    }

                    // Second fork to ensure we can't acquire a controlling terminal
                    match unsafe { libc::fork() } {
                        -1 => {
                            eprintln!(
                                "Failed to fork second time: {}",
                                std::io::Error::last_os_error()
                            );
                            std::process::exit(1);
                        }
                        0 => {
                            // Grandchild - the actual daemon
                            // Continue execution
                            Ok(())
                        }
                        _ => {
                            // First child exits
                            std::process::exit(0);
                        }
                    }
                }
                child_pid => {
                    // Parent process
                    unsafe {
                        libc::close(write_fd);
                    }

                    // Read connection params from pipe
                    let mut read_file = unsafe { std::fs::File::from_raw_fd(read_fd) };
                    let mut buffer = String::new();
                    read_file.read_to_string(&mut buffer)?;
                    std::mem::forget(read_file); // Don't close the fd twice
                    unsafe {
                        libc::close(read_fd);
                    }

                    // Wait for first child to exit
                    let mut status = 0;
                    unsafe {
                        libc::waitpid(child_pid, &mut status, 0);
                    }

                    // Parent exits
                    std::process::exit(0);
                }
            }
        }

        #[cfg(not(unix))]
        {
            // On non-Unix platforms, just return
            Ok(())
        }
    }

    /// Bind to a UDP socket synchronously to find an available port
    pub fn bind_available_port(addr: SocketAddr) -> Result<(UdpSocket, SocketAddr)> {
        let socket = UdpSocket::bind(addr).with_context(|| format!("Failed to bind to {addr}"))?;

        // Get the actual bound address (important when port is 0)
        let bound_addr = socket.local_addr().context("Failed to get local address")?;

        info!("Bound UDP socket to {}", bound_addr);

        Ok((socket, bound_addr))
    }

    /// Generate a self-signed certificate for one-shot mode
    pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
        use rcgen::{Certificate, CertificateParams, DistinguishedName};

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName("localhost".to_string()),
            rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            rcgen::SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        ];

        let cert = Certificate::from_params(params)
            .map_err(|e| anyhow::anyhow!("Failed to generate certificate: {}", e))?;

        let cert_pem = cert
            .serialize_pem()
            .map_err(|e| anyhow::anyhow!("Failed to serialize certificate: {}", e))?;
        let key_pem = cert.serialize_private_key_pem();

        Ok((cert_pem.into_bytes(), key_pem.into_bytes()))
    }

    /// Generate bootstrap connection parameters for one-shot mode
    pub fn generate_bootstrap_params(
        bound_addr: SocketAddr,
        session_key: &[u8],
        log_file_path: &PathBuf,
    ) -> BootstrapConnectParams {
        use base64::Engine;
        let encoded_key = base64::engine::general_purpose::STANDARD.encode(session_key);

        // Following mosh's approach: server does NOT report IP
        // Client will determine IP from the SSH connection or proxy
        BootstrapConnectParams {
            ip: String::new(), // Empty - will be determined by client
            port: bound_addr.port(),
            session_key: encoded_key,
            log_file: Some(log_file_path.display().to_string()),
            client_addr: None,
        }
    }
}
