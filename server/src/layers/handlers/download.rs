use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;
use common::config;
use common::payloads::custom::answer::{Answer, Response};
use common::payloads::custom::command::{Command, Request};
use common::payloads::PayloadFormat;
use common::utils::format_bytes;
use tokio::io::{stderr, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tokio::time::Instant;

use super::{EventLayer, Handler, HandlerResult};

async fn _expect_download<C>(
    ptr: Arc<EventLayer<C>>,
    true_addr: SocketAddr,
    request_id: u32,
    dest: PathBuf,
    sender: mpsc::UnboundedSender<Vec<u8>>,
) where
    C: Cipher + 'static,
{
    let mut file = match tokio::fs::File::create_new(&dest).await {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to create file {}: {}", dest.to_string_lossy(), e);
            match Command::new(!request_id, Request::Cancel(request_id))
                .to_payload()
                .await
            {
                Ok(payload) => {
                    if let Err(e) = sender.send(payload) {
                        eprintln!("Failed to send cancel request: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Unable to create cancel request: {}", e);
                }
            }

            return;
        }
    };

    let mut receiver = ptr.subscribe();
    let mut size = 0;
    let mut chunks_count = 0;

    let mut benchmark_size = size;
    let mut benchmark_time = Instant::now();

    loop {
        if let Ok((addr, packet)) = receiver.recv().await {
            if addr == true_addr {
                if let Ok(answer) = Answer::from_packet(&packet).await {
                    if answer.request_id() == request_id {
                        match answer.answer() {
                            Response::DownloadChunk(total, data) => {
                                if data.is_empty() {
                                    println!(
                                        "\nDownloaded {} to {}",
                                        format_bytes(size as u64),
                                        dest.to_string_lossy()
                                    );
                                    return;
                                }

                                if let Err(e) = file.write_all(data).await {
                                    eprintln!(
                                        "\nFailed to write to file {}: {}",
                                        dest.to_string_lossy(),
                                        e
                                    );
                                    return;
                                }

                                size += data.len();
                                chunks_count += 1;

                                if chunks_count % (config::ACK_CHUNKS_COUNT / 2) == 0 {
                                    match Command::new(
                                        !request_id,
                                        Request::DownloadAck(request_id, size as u64),
                                    )
                                    .to_payload()
                                    .await
                                    {
                                        Ok(payload) => {
                                            if let Err(e) = sender.send(payload) {
                                                eprintln!("Failed to send ACK payload: {}", e);
                                                return;
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Failed to create ACK payload: {}", e);
                                            return;
                                        }
                                    }
                                }

                                if chunks_count % 100 == 0 {
                                    let delta = size - benchmark_size;
                                    benchmark_size = size;
                                    let elapsed = benchmark_time.elapsed();
                                    benchmark_time = Instant::now();

                                    let speed = delta as f64 / elapsed.as_secs_f64();
                                    eprint!(
                                        "\rDownloading: {}/{} ({}/s)    ",
                                        format_bytes(size as u64),
                                        format_bytes(*total),
                                        format_bytes(speed as u64)
                                    );
                                    let _ = stderr().flush().await;
                                }
                            }
                            Response::Error(message) => {
                                eprintln!("Error from peer: {}", message);
                                return;
                            }
                            resp => {
                                eprintln!("Unexpected response type: {:?}", resp);
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

pub struct DownloadHandler;

#[async_trait]
impl<C> Handler<C> for DownloadHandler
where
    C: Cipher + 'static,
{
    async fn run(
        &self,
        ptr: Arc<EventLayer<C>>,
        clients: &RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>,
        request_id: u32,
        matches: clap::ArgMatches,
    ) -> HandlerResult {
        let addr = matches.get_one::<SocketAddr>("addr").unwrap();
        let src = matches.get_one::<PathBuf>("src").unwrap();
        let dest = matches.get_one::<PathBuf>("dest").unwrap();

        let clients = clients.read().await;
        match clients.get(addr) {
            Some(sender) => {
                if let Ok(payload) = Command::new(request_id, Request::Download(src.into()))
                    .to_payload()
                    .await
                {
                    let task = tokio::spawn(_expect_download::<C>(
                        ptr.clone(),
                        *addr,
                        request_id,
                        dest.clone(),
                        sender.clone(),
                    ));

                    if sender.send(payload).is_ok() {
                        if let Err(e) = task.await {
                            eprintln!("Error while downloading: {}", e);
                        }

                        return HandlerResult::noop();
                    }
                }

                eprintln!("Unable to send packet to {}", addr);
            }
            None => {
                eprintln!("No client with address {}", addr);
            }
        }

        HandlerResult::noop()
    }
}
