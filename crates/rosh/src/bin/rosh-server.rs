use std::env;
use std::process;

use rosh::bootstrap::{bootstrap_server, perform_udp_handshake_server};

fn main() {
    let args: Vec<String> = env::args().collect();

    // For now, we only support "new" command
    if args.len() < 2 || args[1] != "new" {
        eprintln!("Usage: {} new", args[0]);
        process::exit(1);
    }

    // Bootstrap the server
    match bootstrap_server(None) {
        Ok((socket, session_key)) => {
            // Fork would happen here in the real implementation
            // For now, we'll just continue in the same process

            // Wait for client connection
            match perform_udp_handshake_server(&socket, &session_key) {
                Ok(client_addr) => {
                    println!("Client connected from: {client_addr}");

                    // In a real implementation, we would:
                    // 1. Spawn a shell process
                    // 2. Start the state synchronization protocol
                    // 3. Handle terminal I/O

                    // For now, just keep the connection alive
                    loop {
                        let mut buf = [0u8; 1024];
                        match socket.recv_from(&mut buf) {
                            Ok((len, addr)) => {
                                if addr == client_addr {
                                    let msg = String::from_utf8_lossy(&buf[..len]);
                                    println!("Received: {msg}");

                                    // Echo back for testing
                                    socket.send_to(&buf[..len], addr).ok();
                                }
                            }
                            Err(e) => {
                                eprintln!("Error receiving data: {e}");
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Handshake failed: {e}");
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to bootstrap server: {e}");
            process::exit(1);
        }
    }
}
