use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;
use common::payloads::disconnect::Disconnect;
use common::payloads::PayloadFormat;
use tokio::sync::{mpsc, RwLock};

use super::super::{EventLayer, Handler, HandlerResult};

pub struct ClientDisconnectHandler;

#[async_trait]
impl<C> Handler<C> for ClientDisconnectHandler
where
    C: Cipher + 'static,
{
    async fn run(
        &self,
        _: Arc<EventLayer<C>>,
        clients: &RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>,
        _: u32,
        matches: clap::ArgMatches,
    ) -> HandlerResult {
        let payload = match Disconnect::new(11, "Disconnected by server", "")
            .to_payload()
            .await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to create disconnect payload: {}", e);
                return HandlerResult::noop();
            }
        };

        for addr in matches.get_many::<SocketAddr>("addr").unwrap() {
            let mut clients = clients.write().await;
            match clients.remove(addr) {
                Some(sender) => {
                    let _ = sender.send(payload.clone());
                }
                None => {
                    eprintln!("No client with address {}", addr);
                }
            }
        }

        HandlerResult::noop()
    }
}
