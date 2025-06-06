use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;
use tokio::sync::{mpsc, RwLock};

use super::{EventLayer, Handler, HandlerResult};

pub struct TargetHandler;

#[async_trait]
impl<C> Handler<C> for TargetHandler
where
    C: Cipher + 'static,
{
    async fn run(
        &self,
        _: Arc<EventLayer<C>>,
        _: &RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>,
        _: u32,
        matches: clap::ArgMatches,
    ) -> HandlerResult {
        let addr = matches.get_one::<SocketAddr>("addr");
        match addr {
            Some(addr) => println!("Setting primary target to {}", addr),
            None => println!("Clearing primary target"),
        }

        HandlerResult::update_target(addr.copied())
    }
}
