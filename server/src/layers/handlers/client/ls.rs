use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;
use common::payloads::custom::ping::Ping;
use common::payloads::custom::pong::Pong;
use common::payloads::disconnect::Disconnect;
use common::payloads::PayloadFormat;
use common::utils::ConsoleTable;
use tokio::sync::{mpsc, RwLock};
use tokio::time::timeout;

use super::super::{EventLayer, Handler, HandlerResult};

async fn _expect_pong<C>(ptr: Arc<EventLayer<C>>, true_addr: SocketAddr, true_value: u8) -> String
where
    C: Cipher + Clone + Send + Sync + 'static,
{
    ptr.wait_for(async |addr, packet| {
        if addr == true_addr {
            if let Ok(pong) = Pong::from_packet(&packet).await {
                if pong.data() == true_value {
                    return Some(pong.version().to_string());
                }
            }
        }

        None
    })
    .await
}

pub struct ClientLsHandler;

#[async_trait]
impl<C> Handler<C> for ClientLsHandler
where
    C: Cipher + 'static,
{
    async fn run(
        &self,
        ptr: Arc<EventLayer<C>>,
        clients: &RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>,
        request_id: u32,
        _: clap::ArgMatches,
    ) -> HandlerResult {
        let ping_value = request_id as u8; // truncate
        match Ping::new(ping_value).to_payload().await {
            Ok(payload) => {
                let mut wait = vec![];
                {
                    let clients = clients.read().await;
                    for (addr, sender) in clients.iter() {
                        wait.push((
                            *addr,
                            // Even though `_expect_pong` may time out in the middle of stream reading (and thus
                            // end up in a random position in the stream), this is still acceptable because it
                            // is regarded as a timeout and the client will be disconnected afterwards.
                            //
                            // A slow RTT of ~5 seconds can be considered as a timeout, right? :)
                            tokio::spawn(timeout(
                                Duration::from_secs(5),
                                _expect_pong::<C>(ptr.clone(), *addr, ping_value),
                            )),
                        ));

                        let _ = sender.send(payload.clone());
                    }
                }

                let mut table =
                    ConsoleTable::new(["Address".to_string(), "Version string".to_string()]);
                let disconnect = Disconnect::new(11, "Disconnected by server", "")
                    .to_payload()
                    .await
                    .ok();
                let mut clients = clients.write().await;
                for (addr, f) in wait {
                    match f.await {
                        Ok(Ok(version)) => {
                            table.add_row([addr.to_string(), version]);
                        }
                        _ => {
                            if let Some(sender) = clients.remove(&addr) {
                                if let Some(payload) = disconnect.clone() {
                                    let _ = sender.send(payload);
                                }
                            }
                        }
                    }
                }

                table.print();
            }
            Err(e) => {
                eprintln!("Unable to create ping payload: {}", e);
            }
        };

        HandlerResult::noop()
    }
}
