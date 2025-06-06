use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use common::cipher::encryption::Cipher;
use common::payloads::custom::answer::{Answer, Response};
use common::payloads::custom::command::{Command, Request};
use common::payloads::PayloadFormat;
use common::utils::{format_bytes, ConsoleTable};
use tokio::sync::{mpsc, RwLock};

use super::{EventLayer, Handler, HandlerResult};

async fn _expect_ls<C>(ptr: Arc<EventLayer<C>>, true_addr: SocketAddr, request_id: u32)
where
    C: Cipher + Clone + Send + Sync + 'static,
{
    ptr.wait_for(async |addr, packet| {
        if addr == true_addr {
            if let Ok(answer) = Answer::from_packet(&packet).await {
                if answer.request_id() == request_id {
                    if let Response::Ls(entries) = answer.answer() {
                        let mut table = ConsoleTable::new([
                            "File Name".to_string(),
                            "File Type".to_string(),
                            "Created At".to_string(),
                            "Modified At".to_string(),
                            "Size (bytes)".to_string(),
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
                        return Some(());
                    }
                }
            }
        }

        None
    })
    .await
}

pub struct LsHandler;

#[async_trait]
impl<C> Handler<C> for LsHandler
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
        let path = matches.get_one::<PathBuf>("path");

        let clients = clients.read().await;
        match clients.get(addr) {
            Some(sender) => {
                let default = PathBuf::from(".");
                if let Ok(payload) = Command::new(
                    request_id,
                    Request::Ls(path.unwrap_or(&default).to_path_buf()),
                )
                .to_payload()
                .await
                {
                    let task = tokio::spawn(_expect_ls::<C>(ptr.clone(), *addr, request_id));

                    if sender.send(payload).is_ok() {
                        let _ = task.await;
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
