use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;
use common::payloads::custom::answer::{Answer, Response};
use common::payloads::custom::command::{Command, Request};
use common::payloads::PayloadFormat;
use tokio::sync::{mpsc, RwLock};

use super::{EventLayer, Handler, HandlerResult};

async fn _expect_pwd<C>(ptr: Arc<EventLayer<C>>, true_addr: SocketAddr, request_id: u32) -> String
where
    C: Cipher + Clone + Send + Sync + 'static,
{
    ptr.wait_for(async |addr, packet| {
        if addr == true_addr {
            if let Ok(answer) = Answer::from_packet(&packet).await {
                if answer.request_id() == request_id {
                    if let Response::Pwd(path) = answer.answer() {
                        return Some(path.to_string_lossy().into_owned());
                    }
                }
            }
        }

        None
    })
    .await
}

pub struct PwdHandler;

#[async_trait]
impl<C> Handler<C> for PwdHandler
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

        let clients = clients.read().await;
        match clients.get(addr) {
            Some(sender) => {
                if let Ok(payload) = Command::new(request_id, Request::Pwd).to_payload().await {
                    let task = tokio::spawn(_expect_pwd::<C>(ptr.clone(), *addr, request_id));

                    if sender.send(payload).is_ok() {
                        match task.await {
                            Ok(path) => {
                                println!("{}", path);
                            }
                            Err(e) => {
                                eprintln!("{}", e);
                            }
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
