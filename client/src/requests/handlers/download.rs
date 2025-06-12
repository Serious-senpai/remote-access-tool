use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;
use common::payloads::custom::request::{Request, RequestType};
use common::payloads::custom::response::{Response, ResponseType};
use common::payloads::PayloadFormat;
use common::utils::{format_bytes, wait_for};
use tokio::fs::File;
use tokio::io::{stderr, stdin, AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::time::Instant;

use crate::broadcast::BroadcastLayer;
use crate::requests::handlers::{Handler, HandlerResult};

pub struct DownloadHandler;

#[async_trait]
impl<C> Handler<C> for DownloadHandler
where
    C: Cipher + 'static,
{
    async fn run(
        &self,
        broadcast: Arc<BroadcastLayer<C>>,
        request_id: u32,
        local_addr: SocketAddr,
        matches: clap::ArgMatches,
    ) -> HandlerResult {
        let addr = *matches.get_one::<SocketAddr>("addr").unwrap();
        let src = matches.get_one::<PathBuf>("src").unwrap();
        let dest = matches.get_one::<PathBuf>("dest").unwrap();

        let file = match File::create_new(dest).await {
            Ok(file) => file,
            Err(_) => {
                let mut stdin = BufReader::new(stdin());
                let mut stderr = stderr();

                loop {
                    eprint!(
                        "{} already exists. Overwrite? (y/n) ",
                        dest.to_string_lossy()
                    );
                    let _ = stderr.flush().await;

                    let mut line = String::new();
                    let _ = stdin.read_line(&mut line).await;
                    line = line.trim().to_string();

                    if line == "y" || line == "yes" {
                        match File::create(dest).await {
                            Ok(file) => break file,
                            Err(e) => {
                                eprintln!("Failed to create file: {}", e);
                                return HandlerResult::noop();
                            }
                        }
                    } else if line == "n" || line == "no" {
                        eprintln!("Request cancelled.");
                        return HandlerResult::noop();
                    }
                }
            }
        };

        // Fast in-memory buffering
        let mut file = BufWriter::new(file);

        let mut receiver = broadcast.subscribe();
        match broadcast
            .send(&Request::new(
                request_id,
                local_addr,
                addr,
                RequestType::Download { path: src.clone() },
            ))
            .await
        {
            Ok(_) => {
                let mut size = 0;
                let mut chunks_count = 0;

                let mut benchmark_size = size;
                let mut benchmark_time = Instant::now();

                loop {
                    let response = wait_for(&mut receiver, async |packet| {
                        if let Ok(response) = Response::from_packet(&packet).await {
                            if response.request_id() == request_id {
                                return Some(response);
                            }
                        }

                        None
                    })
                    .await;

                    match response.rtype() {
                        ResponseType::DownloadChunk { total, data } => {
                            if data.is_empty() {
                                println!(
                                    "\nDownloaded {} to {}",
                                    format_bytes(size as u64),
                                    dest.to_string_lossy()
                                );
                                break;
                            }

                            if let Err(e) = file.write_all(data).await {
                                eprintln!(
                                    "\nFailed to write to file {}: {}",
                                    dest.to_string_lossy(),
                                    e
                                );
                                break;
                            }

                            size += data.len();
                            chunks_count += 1;

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
                        ResponseType::Error { message } => {
                            eprintln!("{}", message);
                            break;
                        }
                        rtype => {
                            eprintln!("Unexpected response type: {:?}", rtype);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to create disconnect payload: {}", e);
                return HandlerResult::noop();
            }
        };

        HandlerResult::noop()
    }
}
