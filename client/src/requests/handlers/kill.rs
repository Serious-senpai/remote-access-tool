use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;
use common::payloads::custom::request::{Request, RequestType};
use common::payloads::custom::response::{Response, ResponseType};
use common::payloads::PayloadFormat;
use common::utils::wait_for;

use crate::broadcast::BroadcastLayer;
use crate::requests::handlers::{Handler, HandlerResult};

pub struct KillHandler;

#[async_trait]
impl<C> Handler<C> for KillHandler
where
    C: Cipher + 'static,
{
    async fn run(
        &self,
        broadcast: Arc<BroadcastLayer<C>>,
        request_id: u32,
        matches: clap::ArgMatches,
    ) -> HandlerResult {
        let addr = *matches.get_one::<SocketAddr>("addr").unwrap();
        let signal = *matches.get_one::<i32>("signal").unwrap();
        let pid = *matches.get_one::<u64>("pid").unwrap();

        let mut receiver = broadcast.subscribe();
        match broadcast
            .send(&Request::new(
                request_id,
                broadcast.local_addr(),
                addr,
                RequestType::Kill { pid, signal },
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
                    ResponseType::Success => {}
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
