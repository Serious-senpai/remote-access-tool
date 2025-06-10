mod broadcast;
mod cli;
mod kex;
mod requests;
mod responses;

use std::error::Error;
use std::sync::Arc;

use broadcast::BroadcastLayer;
use clap::Parser;
use common::cipher::encryption::chacha20_poly1305::ChaCha20Poly1305;
use common::cipher::hostkey::read_host_key;
use common::cipher::hostkey::rsa_sha2_512::RsaSha512;
use common::cipher::kex::curve25519_sha256::Curve25519Sha256;
use common::payloads::custom::query::{Query, QueryType};
use common::payloads::custom::response::{Response, ResponseType};
use common::payloads::PayloadFormat;
use common::utils::wait_for;
use log::{debug, error, info};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = cli::Arguments::parse();

    colog::default_builder()
        .filter_level(arguments.log_level.to_level_filter())
        .filter_module("rustyline", log::LevelFilter::Info)
        .format_source_path(true)
        .init();

    let stream = TcpStream::connect(arguments.address).await?;
    let ssh = kex::key_exchange::<ChaCha20Poly1305, Curve25519Sha256, RsaSha512>(stream).await?;

    let base = Arc::new(BroadcastLayer::new(ssh, 100));
    let main_loop = tokio::spawn(base.clone().listen_loop());

    let task = if let Some(host_key_file) = arguments.admin {
        let (_, rkey) = read_host_key(&host_key_file).await?;
        let payload = Query::new(
            0,
            QueryType::Authenticate {
                rkey: rkey.to_bytes()?.to_vec(),
            },
        );

        let mut receiver = base.subscribe();
        base.send(&payload).await?;
        debug!("Waiting for authentication response...");
        let result = wait_for(&mut receiver, async |packet| {
            if let Ok(response) = Response::from_packet(&packet).await {
                return match response.rtype() {
                    ResponseType::Success => Some(true),
                    _ => Some(false),
                };
            }

            None
        })
        .await;

        if result {
            info!("Authentication successful");
            Some(tokio::spawn(requests::interactive_loop(base.clone())))
        } else {
            error!("Authentication failed");
            None
        }
    } else {
        Some(tokio::spawn(responses::listen_loop(base.clone())))
    };

    if let Some(task) = task {
        let _ = main_loop.await;
        task.abort();
    }

    Ok(())
}
