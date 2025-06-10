use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;
use common::payloads::custom::query::{Query, QueryType};
use common::payloads::custom::response::{Response, ResponseType};
use common::payloads::PayloadFormat;
use common::utils::{wait_for, ConsoleTable};

use crate::broadcast::BroadcastLayer;
use crate::requests::handlers::{Handler, HandlerResult};

pub struct ClientLsHandler;

#[async_trait]
impl<C> Handler<C> for ClientLsHandler
where
    C: Cipher + 'static,
{
    async fn run(
        &self,
        broadcast: Arc<BroadcastLayer<C>>,
        request_id: u32,
        _: SocketAddr,
        _: clap::ArgMatches,
    ) -> HandlerResult {
        let mut receiver = broadcast.subscribe();
        match broadcast
            .send(&Query::new(request_id, QueryType::ClientLs))
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
                    ResponseType::ClientLs { clients } => {
                        let mut table = ConsoleTable::new([
                            "Address".to_string(),
                            "Version string".to_string(),
                            "Admin".to_string(),
                        ]);
                        for client in clients {
                            table.add_row([
                                client.addr.to_string(),
                                client.version.clone(),
                                client.is_admin.to_string(),
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
