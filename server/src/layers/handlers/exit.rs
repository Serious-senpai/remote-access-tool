use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;
use common::payloads::disconnect::Disconnect;
use common::payloads::PayloadFormat;
use tokio::sync::{mpsc, RwLock};

use super::{EventLayer, Handler, HandlerResult};

pub struct ExitHandler;

#[async_trait]
impl<C> Handler<C> for ExitHandler
where
    C: Cipher + 'static,
{
    async fn run(
        &self,
        _: Arc<EventLayer<C>>,
        clients: &RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>,
        _: u32,
        _: clap::ArgMatches,
    ) -> HandlerResult {
        let clients = clients.read().await;

        if let Ok(payload) = Disconnect::new(11, "Server is shutting down", "")
            .to_payload()
            .await
        {
            for (_, sender) in clients.iter() {
                let _ = sender.send(payload.clone());
            }
        }

        HandlerResult::exit()
    }
}
