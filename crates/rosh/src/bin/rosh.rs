use std::env;
use std::io::{self, Write};
use std::process;
use std::thread;
use std::time::Duration;

use rosh::bootstrap::{bootstrap_client, perform_udp_handshake_client};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [user@]host [command...]", args[0]);
        process::exit(1);
    }

    let user_host = &args[1];

    // Bootstrap the connection via SSH
    println!("Connecting to {user_host}...");

    match bootstrap_client(user_host, None, None) {
        Ok(bootstrap_result) => {
            println!(
                "Server is listening on {}:{}",
                bootstrap_result.server_ip, bootstrap_result.server_port
            );

            // Set the MOSH_KEY environment variable (like mosh does)
            env::set_var("MOSH_KEY", &bootstrap_result.session_key);

            // Connect to the server via UDP
            match perform_udp_handshake_client(
                &bootstrap_result.server_ip,
                bootstrap_result.server_port,
                &bootstrap_result.session_key,
            ) {
                Ok(socket) => {
                    println!("Connected successfully!");

                    // In a real implementation, we would:
                    // 1. Start the state synchronization protocol
                    // 2. Handle terminal input/output
                    // 3. Implement speculative local echo

                    // For now, just send a test message every second
                    loop {
                        let message = "PING";
                        match socket.send(message.as_bytes()) {
                            Ok(_) => {
                                print!("Sent: {message} ");
                                io::stdout().flush().ok();

                                // Try to receive response
                                let mut buf = [0u8; 1024];
                                socket.set_read_timeout(Some(Duration::from_secs(1))).ok();

                                match socket.recv(&mut buf) {
                                    Ok(len) => {
                                        let response = String::from_utf8_lossy(&buf[..len]);
                                        println!("Received: {response}");
                                    }
                                    Err(_) => {
                                        println!("(no response)");
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to send: {e}");
                                break;
                            }
                        }

                        thread::sleep(Duration::from_secs(1));
                    }
                }
                Err(e) => {
                    eprintln!("Failed to connect via UDP: {e}");
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Bootstrap failed: {e}");
            process::exit(1);
        }
    }
}
