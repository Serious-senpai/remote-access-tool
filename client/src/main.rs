mod cli;
mod kex;

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fmt::Debug;
use std::path::PathBuf;
use std::time::SystemTime;

use clap::Parser;
use common::cipher::encryption::chacha20_poly1305::ChaCha20Poly1305;
use common::cipher::encryption::Cipher;
use common::cipher::hostkey::rsa_sha2_512::RsaSha512;
use common::cipher::kex::curve25519_sha256::Curve25519Sha256;
use common::packets::Packet;
use common::payloads::custom::answer::{Answer, Entry, EntryMetadata, Response};
use common::payloads::custom::command::{Command, Request};
use common::payloads::custom::ping::Ping;
use common::payloads::custom::pong::Pong;
use common::payloads::disconnect::Disconnect;
use common::payloads::PayloadFormat;
use common::ssh::SSH;
use common::utils::format_bytes;
use common::{config, log_error};
use log::{debug, error, info, warn};
use tokio::fs::read_dir;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::signal;
use tokio::sync::{broadcast, mpsc};

async fn listen_loop<C>(
    mut ssh: SSH<C>,
    sender: broadcast::Sender<Packet<C>>,
    mut receiver: mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    C: Cipher + Debug,
{
    loop {
        tokio::select! {
            Some(payload) = receiver.recv() => {
                if let Err(e) = ssh.write_raw_payload(payload).await {
                    error!("Unable to send packet: {}", e);
                    return Err(e)?;
                }
            }
            _ = ssh.peek() => {
                let packet = log_error!(ssh.read_packet().await);
                debug!("Received {:?}", packet);
                if let Err(e) = sender.send(packet) {
                    error!("Received a packet, but unable to notify higher levels: {}", e);
                }
            }
            _ = signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
                let disconnect = Disconnect::new(11, "Client shutdown", "");
                let packet = ssh.write_payload(&disconnect).await?;
                let _ = sender.send(packet);
                break;
            }
        }
    }

    Ok(())
}

async fn pwd(
    sender: mpsc::UnboundedSender<Vec<u8>>,
    payload: Command,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Requesting current directory");

    let path = env::current_dir().unwrap_or_default();
    let payload = Answer::new(payload.request_id(), Response::Pwd(path));
    sender.send(payload.to_payload().await?)?;

    Ok(())
}

async fn ls(
    sender: mpsc::UnboundedSender<Vec<u8>>,
    payload: Command,
    path: PathBuf,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Listing directory {}", path.to_string_lossy());

    let payload = match read_dir(&path).await {
        Ok(mut entries) => {
            let mut result = vec![];
            while let Ok(Some(entry)) = entries.next_entry().await {
                let file_name = entry.file_name().to_string_lossy().into_owned();
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
                        created_at: m.created().unwrap_or(SystemTime::UNIX_EPOCH),
                        modified_at: m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                        size: m.len(),
                    })
                    .ok();

                result.push(Entry {
                    file_name,
                    file_type: file_type.to_string(),
                    metadata,
                })
            }

            Answer::new(payload.request_id(), Response::Ls(result))
        }
        Err(e) => Answer::new(
            payload.request_id(),
            Response::Error(format!("Failed to read {}: {}", path.to_string_lossy(), e)),
        ),
    };

    sender.send(payload.to_payload().await?)?;
    Ok(())
}

async fn cd(
    sender: mpsc::UnboundedSender<Vec<u8>>,
    payload: Command,
    path: PathBuf,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Changing directory to {}", path.to_string_lossy());

    let response = match env::set_current_dir(path) {
        Ok(_) => match env::current_dir() {
            Ok(new_path) => Response::Cd(new_path),
            Err(e) => Response::Error(e.to_string()),
        },
        Err(e) => Response::Error(e.to_string()),
    };
    let payload = Answer::new(payload.request_id(), response);
    sender.send(payload.to_payload().await?)?;

    Ok(())
}

async fn download(
    sender: mpsc::UnboundedSender<Vec<u8>>,
    payload: Command,
    mut receiver: broadcast::Receiver<Packet<ChaCha20Poly1305>>,
    path: PathBuf,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    const CHUNK_SIZE: usize = 8192;
    info!("Uploading file {} to server", path.to_string_lossy());

    match tokio::fs::File::open(&path).await {
        Ok(mut file) => {
            let total = match file.metadata().await {
                Ok(metadata) => metadata.len(),
                Err(e) => {
                    warn!("Failed to get metadata: {}", e);
                    0
                }
            };
            let mut sent = 0;
            let mut received = 0;

            loop {
                let mut buf = vec![0; CHUNK_SIZE];
                match file.read(&mut buf).await {
                    Ok(0) => {
                        info!(
                            "File upload complete: {} {}",
                            format_bytes(total),
                            path.to_string_lossy(),
                        );
                        let payload = Answer::new(
                            payload.request_id(),
                            Response::DownloadChunk(total, vec![]),
                        );
                        sender.send(payload.to_payload().await?)?;
                        break;
                    }
                    Ok(n) => {
                        buf.truncate(n);
                        let payload =
                            Answer::new(payload.request_id(), Response::DownloadChunk(total, buf));
                        sender.send(payload.to_payload().await?)?;
                        sent += n;
                    }
                    Err(e) => {
                        error!("Failed to read {}: {}", path.to_string_lossy(), e);
                        let payload =
                            Answer::new(payload.request_id(), Response::Error(e.to_string()));
                        sender.send(payload.to_payload().await?)?;
                        break;
                    }
                }

                if sent >= received + config::ACK_CHUNKS_COUNT * CHUNK_SIZE {
                    loop {
                        if let Ok(packet) = receiver.recv().await {
                            if let Ok(command) = Command::from_packet(&packet).await {
                                if let Request::DownloadAck(request_id, total) = command.command() {
                                    if request_id == &payload.request_id() {
                                        received = *total as usize;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to open {}: {}", path.to_string_lossy(), e);
            let payload = Answer::new(payload.request_id(), Response::Error(e.to_string()));
            sender.send(payload.to_payload().await?)?;
        }
    };

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = cli::Arguments::parse();

    let mut log = colog::default_builder();
    log.filter_level(arguments.log_level.to_level_filter());
    log.init();

    let stream = TcpStream::connect(arguments.address).await?;
    let ssh = kex::key_exchange::<ChaCha20Poly1305, Curve25519Sha256, RsaSha512>(stream).await?;

    let (m_sender, s_receiver) = mpsc::unbounded_channel();
    let (s_sender, mut m_receiver) = broadcast::channel(100);
    tokio::spawn(listen_loop(ssh, s_sender.clone(), s_receiver));

    let mut tasks = HashMap::new();
    loop {
        let packet = match m_receiver.recv().await {
            Ok(packet) => packet,
            Err(error) => {
                error!("Cannot receive packet from lower level: {}", error);
                break;
            }
        };

        let opcode = packet.peek_opcode();
        match opcode {
            Some(Ping::OPCODE) => {
                let payload = Ping::from_packet(&packet).await?;
                let pong = Pong::new(payload.data(), config::SSH_ID_STRING.to_string());
                m_sender.send(pong.to_payload().await?)?;
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
                macro_rules! cmd_handler {
                    ($handler:ident) => {
                        let request_id = payload.request_id();
                        let task = tokio::spawn($handler(m_sender.clone(), payload));
                        tasks.insert(request_id, task);
                    };
                    ($handler:ident, $($args:expr),*) => {
                        let request_id = payload.request_id();
                        let task = tokio::spawn($handler(m_sender.clone(), payload, $($args),*));
                        tasks.insert(request_id, task);
                    };
                }

                match payload.command().clone() {
                    Request::Pwd => {
                        cmd_handler!(pwd);
                    }
                    Request::Ls(path) => {
                        cmd_handler!(ls, path.clone());
                    }
                    Request::Cd(path) => {
                        cmd_handler!(cd, path.clone());
                    }
                    Request::Download(path) => {
                        cmd_handler!(download, s_sender.subscribe(), path.clone());
                    }
                    Request::Cancel(request_id) => match tasks.remove(&request_id) {
                        Some(task) => {
                            info!("Canceling request ID {}", request_id);
                            task.abort();

                            if task.await.is_err() {
                                let payload = Answer::new(
                                    request_id,
                                    Response::Error("Request cancelled".to_string()),
                                );
                                m_sender.send(payload.to_payload().await?)?;
                            }
                        }
                        _ => {
                            warn!("No task found for request ID {}", request_id);
                        }
                    },
                    _ => (),
                }
            }
            opcode => {
                warn!("Unknown opcode {:?}", opcode);
            }
        }
    }

    Ok(())
}
