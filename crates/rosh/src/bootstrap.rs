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
use tracing::{debug, info, warn};

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

/// Connection information returned from SSH bootstrap
#[derive(Debug)]
pub struct BootstrapInfo {
    /// IP address to connect to
    pub ip: IpAddr,
    /// Port number
    pub port: u16,
    /// Session key (base64 encoded)
    pub session_key: String,
    /// Log file path (optional)
    pub log_file: Option<String>,
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
}

impl From<BootstrapInfo> for BootstrapConnectParams {
    fn from(info: BootstrapInfo) -> Self {
        Self {
            ip: info.ip.to_string(),
            port: info.port,
            session_key: info.session_key,
            log_file: info.log_file,
        }
    }
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

/// Bootstrap a Rosh connection via SSH
pub async fn bootstrap_via_ssh(options: BootstrapOptions<'_>) -> Result<BootstrapInfo> {
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
async fn bootstrap_local_resolution(options: BootstrapOptions<'_>) -> Result<BootstrapInfo> {
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

    Ok(BootstrapInfo {
        ip,
        port,
        session_key,
        log_file: None,
    })
}

/// Remote resolution strategy - get IP from SSH_CONNECTION
async fn bootstrap_remote_resolution(options: BootstrapOptions<'_>) -> Result<BootstrapInfo> {
    info!("Using remote IP resolution for {}", options.host);

    // Build SSH target
    let ssh_target = if let Some(user) = options.user {
        format!("{}@{}", user, options.host)
    } else {
        options.host.to_string()
    };

    // Start server via SSH with SSH_CONNECTION capture
    info!("Starting Rosh server via SSH and capturing SSH_CONNECTION");
    let (ip, port, session_key, log_file) =
        start_server_ssh_with_connection(&ssh_target, &options).await?;
    info!("Server started on {}:{} with session key", ip, port);
    if let Some(ref log_path) = log_file {
        info!("Server log file: {}", log_path);
    }

    Ok(BootstrapInfo {
        ip,
        port,
        session_key,
        log_file,
    })
}

/// Proxy resolution strategy - use SSH ProxyCommand
async fn bootstrap_proxy_resolution(options: BootstrapOptions<'_>) -> Result<BootstrapInfo> {
    info!("Using proxy IP resolution for {}", options.host);

    // For proxy mode, we need to implement a fake proxy handler
    // This is complex and would require significant changes to support
    // For now, fall back to remote resolution
    warn!("Proxy mode not yet implemented, falling back to remote resolution");
    bootstrap_remote_resolution(options).await
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
    let (port, session_key, _log_file) = parse_server_output(&output)?;
    Ok((port, session_key))
}

/// Start server via SSH with SSH_CONNECTION capture
async fn start_server_ssh_with_connection(
    ssh_target: &str,
    options: &BootstrapOptions<'_>,
) -> Result<(IpAddr, u16, String, Option<String>)> {
    let mut ssh_cmd = build_ssh_command(ssh_target, options, true);

    // Build remote command with SSH_CONNECTION capture
    let remote_cmd = build_remote_command(options);
    let full_cmd = format!(
        r#"sh -c '[ -n "$SSH_CONNECTION" ] && printf "\nROSH SSH_CONNECTION %s\n" "$SSH_CONNECTION" ; {remote_cmd}'"#
    );
    ssh_cmd.arg(full_cmd);

    // Execute and parse output
    let output = execute_ssh_command(ssh_cmd).await?;
    let (port, session_key, log_file) = parse_server_output(&output)?;

    // Parse SSH_CONNECTION to get server IP
    let ip = parse_ssh_connection(&output)?;

    Ok((ip, port, session_key, log_file))
}

/// Build SSH command with appropriate options
fn build_ssh_command(
    ssh_target: &str,
    options: &BootstrapOptions<'_>,
    needs_family_hint: bool,
) -> Command {
    let mut cmd = Command::new("ssh");

    // Basic SSH options
    cmd.arg("-n"); // No stdin
    cmd.arg("-T"); // No PTY allocation to avoid terminal escape sequences

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
        CipherAlgorithm::Aes128Gcm => args.extend(["--cipher".to_string(), "aes-gcm".to_string()]),
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
                if output.contains("ROSH_CONNECT_PARAMS:") {
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

    // Kill SSH process - the server has already detached
    let _ = child.kill().await;

    if output.is_empty() {
        anyhow::bail!("SSH command produced no output");
    }

    Ok(output)
}

/// Parse server output for connection parameters
fn parse_server_output(output: &str) -> Result<(u16, String, Option<String>)> {
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
        if line.starts_with("ROSH_CONNECT_PARAMS: ") {
            let json_str = line.strip_prefix("ROSH_CONNECT_PARAMS: ").unwrap();
            debug!("Found connection params JSON: {}", json_str);

            let params: BootstrapConnectParams = serde_json::from_str(json_str)
                .context("Failed to parse connection parameters JSON")?;

            return Ok((params.port, params.session_key, log_file));
        }
    }

    anyhow::bail!(
        "Server did not provide connection parameters. Output was:\n{}",
        output.lines().take(20).collect::<Vec<_>>().join("\n")
    )
}

/// Parse SSH_CONNECTION to extract server IP
fn parse_ssh_connection(output: &str) -> Result<IpAddr> {
    for line in output.lines() {
        if line.contains("ROSH SSH_CONNECTION") {
            // Format: ROSH SSH_CONNECTION client_ip client_port server_ip server_port
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let server_ip_str = parts[4];
                let ip = server_ip_str
                    .parse::<IpAddr>()
                    .with_context(|| format!("Failed to parse server IP: {server_ip_str}"))?;
                return Ok(ip);
            }
        }
    }

    anyhow::bail!("SSH_CONNECTION not found in server output")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_ip_strategy_from_str() {
        assert_eq!(
            RemoteIpStrategy::from_str("local").unwrap(),
            RemoteIpStrategy::Local
        );
        assert_eq!(
            RemoteIpStrategy::from_str("remote").unwrap(),
            RemoteIpStrategy::Remote
        );
        assert_eq!(
            RemoteIpStrategy::from_str("proxy").unwrap(),
            RemoteIpStrategy::Proxy
        );
        assert_eq!(
            RemoteIpStrategy::from_str("LOCAL").unwrap(),
            RemoteIpStrategy::Local
        );
        assert!(RemoteIpStrategy::from_str("invalid").is_err());
    }

    #[test]
    fn test_network_family_from_str() {
        assert_eq!(
            NetworkFamily::from_str("inet").unwrap(),
            NetworkFamily::Inet
        );
        assert_eq!(
            NetworkFamily::from_str("ipv4").unwrap(),
            NetworkFamily::Inet
        );
        assert_eq!(NetworkFamily::from_str("4").unwrap(), NetworkFamily::Inet);
        assert_eq!(
            NetworkFamily::from_str("inet6").unwrap(),
            NetworkFamily::Inet6
        );
        assert_eq!(
            NetworkFamily::from_str("ipv6").unwrap(),
            NetworkFamily::Inet6
        );
        assert_eq!(NetworkFamily::from_str("6").unwrap(), NetworkFamily::Inet6);
        assert_eq!(NetworkFamily::from_str("all").unwrap(), NetworkFamily::All);
        assert_eq!(
            NetworkFamily::from_str("prefer-inet").unwrap(),
            NetworkFamily::PreferInet
        );
        assert_eq!(
            NetworkFamily::from_str("prefer-ipv6").unwrap(),
            NetworkFamily::PreferInet6
        );
        assert!(NetworkFamily::from_str("invalid").is_err());
    }

    #[test]
    fn test_parse_server_output() {
        let output = r#"
Starting Rosh server on 0.0.0.0:2022
ROSH_PORT=2022
ROSH_KEY=QTmjegDO4+NBlwqAF2MCMEa/NBqJPeba8ypiKSfEiRA=
Server listening on 0.0.0.0:2022
"#;

        let (port, key, _log_file) = parse_server_output(output).unwrap();
        assert_eq!(port, 2022);
        assert_eq!(key, "QTmjegDO4+NBlwqAF2MCMEa/NBqJPeba8ypiKSfEiRA=");
    }

    #[test]
    fn test_parse_ssh_connection() {
        let output = r#"
Some other output
ROSH SSH_CONNECTION 192.168.1.100 54321 192.168.1.200 22
More output
"#;

        let ip = parse_ssh_connection(output).unwrap();
        assert_eq!(ip.to_string(), "192.168.1.200");
    }

    #[test]
    fn test_parse_ssh_connection_ipv6() {
        let output = r#"
ROSH SSH_CONNECTION 2001:db8::1 54321 2001:db8::2 22
"#;

        let ip = parse_ssh_connection(output).unwrap();
        assert_eq!(ip.to_string(), "2001:db8::2");
    }
}
