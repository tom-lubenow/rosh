use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::{engine::general_purpose, Engine as _};
use rand::Rng;

/// The port range that rosh-server will try to bind to
const DEFAULT_PORT_RANGE: (u16, u16) = (60000, 61000);

/// Timeout for server startup
const SERVER_STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

/// Result of the bootstrap process
#[derive(Debug)]
pub struct BootstrapResult {
    pub server_ip: String,
    pub server_port: u16,
    pub session_key: String,
}

/// Bootstrap the rosh connection using SSH
pub fn bootstrap_client(
    user_host: &str,
    server_command: Option<&str>,
    ssh_command: Option<&str>,
) -> io::Result<BootstrapResult> {
    let ssh = ssh_command.unwrap_or("ssh");
    let server = server_command.unwrap_or("rosh-server");

    // Build SSH command with -n (no stdin) and -tt (allocate pseudo-tty)
    let mut ssh_process = Command::new(ssh)
        .arg("-n")
        .arg("-tt")
        .arg(user_host)
        .arg("--")
        .arg(format!("{server} new"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = ssh_process.stdout.take().expect("Failed to get stdout");
    let reader = BufReader::new(stdout);

    let mut server_ip = None;
    let mut server_port = None;
    let mut session_key = None;

    // Read output line by line looking for MOSH CONNECT message
    for line in reader.lines() {
        let line = line?;
        println!("{line}"); // Echo other output

        if line.starts_with("MOSH IP ") {
            // Extract IP from "MOSH IP x.x.x.x" format
            server_ip = line.strip_prefix("MOSH IP ").map(|s| s.trim().to_string());
        } else if line.starts_with("MOSH CONNECT ") {
            // Parse "MOSH CONNECT port key" format
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == "MOSH" && parts[1] == "CONNECT" {
                server_port = parts[2].parse().ok();
                session_key = Some(parts[3].to_string());
                break;
            }
        }
    }

    // Wait for SSH process to complete
    let status = ssh_process.wait()?;

    if !status.success() {
        return Err(io::Error::other("SSH command failed"));
    }

    // If we didn't get an IP from MOSH IP message, use the host from SSH connection
    let server_ip = server_ip.unwrap_or_else(|| {
        // In a real implementation, we'd resolve the hostname or extract from SSH_CONNECTION
        // For now, just use the host part of user_host
        user_host
            .split('@')
            .next_back()
            .unwrap_or(user_host)
            .to_string()
    });

    match (server_port, session_key) {
        (Some(port), Some(key)) => Ok(BootstrapResult {
            server_ip,
            server_port: port,
            session_key: key,
        }),
        _ => Err(io::Error::other("Did not find rosh server startup message")),
    }
}

/// Generate a 128-bit session key and encode it as base64-like string
pub fn generate_session_key() -> String {
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();
    general_purpose::STANDARD.encode(key)
}

/// Server-side bootstrap: bind UDP socket and print connection info
pub fn bootstrap_server(port_range: Option<(u16, u16)>) -> io::Result<(UdpSocket, String)> {
    let (start_port, end_port) = port_range.unwrap_or(DEFAULT_PORT_RANGE);

    // Try to bind to a port in the range
    let mut socket = None;
    let mut bound_port = 0;

    for port in start_port..=end_port {
        match UdpSocket::bind(("0.0.0.0", port)) {
            Ok(s) => {
                socket = Some(s);
                bound_port = port;
                break;
            }
            Err(_) => continue,
        }
    }

    let socket = socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("Could not bind to any port in range {start_port}-{end_port}"),
        )
    })?;

    // Generate session key
    let session_key = generate_session_key();

    // Print the MOSH CONNECT message to stdout
    println!("MOSH CONNECT {bound_port} {session_key}");
    io::stdout().flush()?;

    // Set read timeout for initial client connection
    socket.set_read_timeout(Some(SERVER_STARTUP_TIMEOUT))?;

    Ok((socket, session_key))
}

/// Simple UDP handshake for testing
pub fn perform_udp_handshake_client(
    server_addr: &str,
    server_port: u16,
    session_key: &str,
) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let server_addr = format!("{server_addr}:{server_port}");

    // Send initial packet with session key
    let message = format!("HELLO {session_key}");
    socket.send_to(message.as_bytes(), &server_addr)?;

    // Wait for response
    let mut buf = [0u8; 1024];
    let (len, _addr) = socket.recv_from(&mut buf)?;
    let response = String::from_utf8_lossy(&buf[..len]);

    if response.starts_with("WELCOME") {
        println!("Connected to server");
        Ok(socket)
    } else {
        Err(io::Error::other("Invalid server response"))
    }
}

/// Simple UDP handshake for testing
pub fn perform_udp_handshake_server(
    socket: &UdpSocket,
    expected_key: &str,
) -> io::Result<SocketAddr> {
    let mut buf = [0u8; 1024];

    // Wait for client hello
    let (len, client_addr) = socket.recv_from(&mut buf)?;
    let message = String::from_utf8_lossy(&buf[..len]);

    if let Some(key) = message.strip_prefix("HELLO ") {
        if key.trim() == expected_key {
            // Send welcome response
            socket.send_to(b"WELCOME", client_addr)?;
            println!("Client connected from {client_addr}");
            return Ok(client_addr);
        }
    }

    Err(io::Error::other("Invalid client handshake"))
}
