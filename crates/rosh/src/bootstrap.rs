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
    let (port, session_key) = start_server_ssh(&ssh_target, &options).await?;

    Ok(BootstrapInfo {
        ip,
        port,
        session_key,
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
    let (ip, port, session_key) = start_server_ssh_with_connection(&ssh_target, &options).await?;

    Ok(BootstrapInfo {
        ip,
        port,
        session_key,
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
    parse_server_output(&output)
}

/// Start server via SSH with SSH_CONNECTION capture
async fn start_server_ssh_with_connection(
    ssh_target: &str,
    options: &BootstrapOptions<'_>,
) -> Result<(IpAddr, u16, String)> {
    let mut ssh_cmd = build_ssh_command(ssh_target, options, true);

    // Build remote command with SSH_CONNECTION capture
    let remote_cmd = build_remote_command(options);
    let full_cmd = format!(
        r#"sh -c '[ -n "$SSH_CONNECTION" ] && printf "\nROSH SSH_CONNECTION %s\n" "$SSH_CONNECTION" ; {remote_cmd}'"#
    );
    ssh_cmd.arg(full_cmd);

    // Execute and parse output
    let output = execute_ssh_command(ssh_cmd).await?;
    let (port, session_key) = parse_server_output(&output)?;

    // Parse SSH_CONNECTION to get server IP
    let ip = parse_ssh_connection(&output)?;

    Ok((ip, port, session_key))
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
    cmd.arg("-tt"); // Allocate PTY

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
    let mut child = cmd.spawn().context("Failed to spawn SSH process")?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to get stdout from SSH"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to get stderr from SSH"))?;

    let mut stdout_reader = BufReader::new(stdout);
    let mut stderr_reader = BufReader::new(stderr);
    let mut output = String::new();

    let timeout = Duration::from_secs(10);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!("Timeout waiting for server to start");
        }

        let mut stdout_line = String::new();
        let mut stderr_line = String::new();

        tokio::select! {
            result = stdout_reader.read_line(&mut stdout_line) => {
                if result? == 0 {
                    break; // EOF
                }
                output.push_str(&stdout_line);
                debug!("SSH stdout: {}", stdout_line.trim());
            }

            result = stderr_reader.read_line(&mut stderr_line) => {
                if result? > 0 {
                    output.push_str(&stderr_line);
                    debug!("SSH stderr: {}", stderr_line.trim());
                }
            }

            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Check if we have the required output
                if output.contains("ROSH_PORT=") && output.contains("ROSH_KEY=") {
                    break;
                }
            }
        }
    }

    // Kill SSH process
    let _ = child.kill().await;

    // Log the full output for debugging
    if output.is_empty() {
        warn!("SSH command produced no output");
    } else {
        debug!("Full SSH output:\n{}", output);
    }

    Ok(output)
}

/// Parse server output for port and session key
fn parse_server_output(output: &str) -> Result<(u16, String)> {
    let mut port = None;
    let mut session_key = None;

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("ROSH_PORT=") {
            port = Some(
                line.strip_prefix("ROSH_PORT=")
                    .unwrap()
                    .parse::<u16>()
                    .context("Failed to parse port")?,
            );
        } else if line.starts_with("ROSH_KEY=") {
            session_key = Some(line.strip_prefix("ROSH_KEY=").unwrap().to_string());
        }
    }

    let port = port.ok_or_else(|| {
        anyhow::anyhow!(
            "Server did not provide port. Output was:\n{}",
            output.lines().take(20).collect::<Vec<_>>().join("\n")
        )
    })?;
    let session_key = session_key.ok_or_else(|| {
        anyhow::anyhow!(
            "Server did not provide session key. Output was:\n{}",
            output.lines().take(20).collect::<Vec<_>>().join("\n")
        )
    })?;

    Ok((port, session_key))
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

        let (port, key) = parse_server_output(output).unwrap();
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
