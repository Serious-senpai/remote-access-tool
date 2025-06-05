mod cli;
mod kex;

use std::env;
use std::error::Error;
use std::time::SystemTime;

use clap::Parser;
use common::cipher::encryption::chacha20_poly1305::ChaCha20Poly1305;
use common::cipher::hostkey::rsa_sha2_512::RsaSha512;
use common::cipher::kex::curve25519_sha256::Curve25519Sha256;
use common::config;
use common::payloads::custom::answer::{Answer, Entry, EntryMetadata, Response};
use common::payloads::custom::command::{Command, Request};
use common::payloads::custom::ping::Ping;
use common::payloads::custom::pong::Pong;
use common::payloads::disconnect::Disconnect;
use common::payloads::PayloadFormat;
use log::{debug, error, info, warn};
use tokio::fs::read_dir;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = cli::Arguments::parse();

    let mut log = colog::default_builder();
    log.filter_level(arguments.log_level.to_level_filter());
    log.init();

    let stream = TcpStream::connect(arguments.address).await?;
    let mut ssh =
        kex::key_exchange::<ChaCha20Poly1305, Curve25519Sha256, RsaSha512>(stream).await?;

    loop {
        let packet = ssh.read_packet().await?;
        let opcode = packet.peek_opcode();
        debug!("Received {:?} (opcode {:?})", packet, opcode);
        match opcode {
            Some(Ping::OPCODE) => {
                let payload = Ping::from_packet(&packet).await?;
                let pong = Pong::new(payload.data(), config::SSH_ID_STRING.to_string());
                ssh.write_payload(&pong).await?;
            }
            Some(Disconnect::OPCODE) => {
                let payload = Disconnect::from_packet(&packet).await?;
                info!(
                    "Server disconnected (code: {}, description: {})",
                    payload.reason_code(),
                    payload.description()
                );

                break;
            }
            Some(Command::OPCODE) => {
                let payload = Command::from_packet(&packet).await?;
                match payload.command() {
                    Request::Pwd => {
                        info!("Requesting current directory");
                        let path = env::current_dir().unwrap_or_default();
                        let payload = Answer::new(payload.request_id(), Response::Pwd(path));
                        ssh.write_payload(&payload).await?;
                    }
                    Request::Ls(path) => {
                        info!("Listing directory {}", path.to_string_lossy());
                        let entries = match read_dir(path).await {
                            Ok(mut entries) => {
                                let mut result = vec![];
                                while let Ok(Some(entry)) = entries.next_entry().await {
                                    let file_name =
                                        entry.file_name().to_string_lossy().into_owned();
                                    let file_type = match entry.file_type().await {
                                        Ok(t) => {
                                            if t.is_dir() {
                                                "dir"
                                            } else if t.is_file() {
                                                "file"
                                            } else if t.is_symlink() {
                                                "symlink"
                                            } else {
                                                "unknown"
                                            }
                                        }
                                        Err(_) => "unknown",
                                    };
                                    let metadata = entry
                                        .metadata()
                                        .await
                                        .map(|m| EntryMetadata {
                                            created_at: m
                                                .created()
                                                .unwrap_or(SystemTime::UNIX_EPOCH),
                                            modified_at: m
                                                .modified()
                                                .unwrap_or(SystemTime::UNIX_EPOCH),
                                            size: m.len(),
                                        })
                                        .ok();

                                    result.push(Entry {
                                        file_name,
                                        file_type: file_type.to_string(),
                                        metadata,
                                    })
                                }

                                result
                            }
                            Err(e) => {
                                error!("Failed to read directory {:?}: {}", path, e);
                                vec![]
                            }
                        };

                        let payload = Answer::new(payload.request_id(), Response::Ls(entries));
                        ssh.write_payload(&payload).await?;
                    }
                    Request::Cd(path) => {
                        info!("Changing directory to {}", path.to_string_lossy());
                        let message = match env::set_current_dir(path) {
                            Ok(_) => "".to_string(),
                            Err(e) => e.to_string(),
                        };
                        let path = env::current_dir().unwrap_or_default();
                        let payload =
                            Answer::new(payload.request_id(), Response::Cd(path, message));
                        ssh.write_payload(&payload).await?;
                    }
                }
            }
            opcode => {
                warn!("Unknown opcode {:?}", opcode);
            }
        }
    }

    Ok(())
}
