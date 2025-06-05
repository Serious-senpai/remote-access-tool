mod cli;
mod kex;

use std::env;
use std::error::Error;
use std::path::PathBuf;

use clap::Parser;
use common::cipher::encryption::chacha20_poly1305::ChaCha20Poly1305;
use common::cipher::hostkey::rsa_sha2_512::RsaSha512;
use common::cipher::kex::curve25519_sha256::Curve25519Sha256;
use common::config;
use common::payloads::custom::cwd::Cwd;
use common::payloads::custom::ls::ListDir;
use common::payloads::custom::ping::Ping;
use common::payloads::custom::pong::Pong;
use common::payloads::custom::request::{Command, Request};
use common::payloads::disconnect::Disconnect;
use common::payloads::PayloadFormat;
use log::{debug, info, warn};
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
            Some(Request::OPCODE) => {
                let payload = Request::from_packet(&packet).await?;
                match payload.command() {
                    Command::Pwd => {
                        let payload = Cwd::new();
                        ssh.write_payload(&payload).await?;
                    }
                    Command::Ls(path) => {
                        let default = PathBuf::from(".");
                        let path = path.as_ref().unwrap_or(&default);
                        let payload = ListDir::new(&path);
                        ssh.write_payload(&payload).await?;
                    }
                    Command::Cd(path) => {
                        let _ = env::set_current_dir(path);
                        let payload = Cwd::new();
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
