use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use common::cipher::encryption::Cipher;
use common::payloads::custom::request::{Request, RequestType};
use common::payloads::custom::response::{Response, ResponseType};
use common::payloads::PayloadFormat;
use common::utils::{format_bytes, wait_for, ConsoleTable};

use crate::requests::handlers::{Handler, HandlerResult};
use crate::broadcast::BroadcastLayer;

pub struct LsHandler;

#[async_trait]
impl<C> Handler<C> for LsHandler
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
        let path = matches.get_one::<PathBuf>("path").unwrap();

        let mut receiver = broadcast.subscribe();
        match broadcast
            .send(&Request::new(
                request_id,
                local_addr,
                addr,
                RequestType::Ls { path: path.clone() },
            ))
            .await
        {
            Ok(_) => {
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
                    ResponseType::Ls { entries } => {
                        let mut table = ConsoleTable::new([
                            "File name".to_string(),
                            "File type".to_string(),
                            "Created at".to_string(),
                            "Modified at".to_string(),
                            "Size".to_string(),
                        ]);
                        for entry in entries {
                            let (created_at, modified_at, formatted_size) = match &entry.metadata {
                                Some(metadata) => {
                                    let created_at = DateTime::<Utc>::from(metadata.created_at)
                                        .format("%Y-%m-%d %H:%M:%S")
                                        .to_string();
                                    let modified_at = DateTime::<Utc>::from(metadata.modified_at)
                                        .format("%Y-%m-%d %H:%M:%S")
                                        .to_string();
                                    (created_at, modified_at, format_bytes(metadata.size))
                                }
                                None => ("N/A".to_string(), "N/A".to_string(), "N/A".to_string()),
                            };
                            table.add_row([
                                entry.file_name.clone(),
                                entry.file_type.clone(),
                                created_at,
                                modified_at,
                                formatted_size,
                            ]);
                        }
                        table.print();
                    }
                    ResponseType::Error { message } => {
                        eprintln!("{}", message);
                    }
                    rtype => {
                        eprintln!("Unexpected response type: {:?}", rtype);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to send payload: {}", e);
                return HandlerResult::noop();
            }
        };

        HandlerResult::noop()
    }
}
