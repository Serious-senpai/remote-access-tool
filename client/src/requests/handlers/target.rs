use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;

use crate::requests::handlers::{Handler, HandlerResult};
use crate::broadcast::BroadcastLayer;

pub struct TargetHandler;

#[async_trait]
impl<C> Handler<C> for TargetHandler
where
    C: Cipher + 'static,
{
    async fn run(
        &self,
        _: Arc<BroadcastLayer<C>>,
        _: u32,
        _: SocketAddr,
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
