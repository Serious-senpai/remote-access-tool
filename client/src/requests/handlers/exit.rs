use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;

use crate::broadcast::BroadcastLayer;
use crate::requests::handlers::{Handler, HandlerResult};

pub struct ExitHandler;

#[async_trait]
impl<C> Handler<C> for ExitHandler
where
    C: Cipher + 'static,
{
    async fn run(
        &self,
        broadcast: Arc<BroadcastLayer<C>>,
        _: u32,
        _: SocketAddr,
        _: clap::ArgMatches,
    ) -> HandlerResult {
        broadcast.exit().await;
        HandlerResult::exit()
    }
}
