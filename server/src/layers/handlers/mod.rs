pub mod cd;
pub mod client;
pub mod download;
pub mod exit;
pub mod ls;
pub mod pwd;
pub mod target;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;
use tokio::sync::{mpsc, RwLock};

use super::events::EventLayer;

pub struct HandlerResult {
    pub exit: bool,
    pub set_target: SetTarget,
}

impl HandlerResult {
    pub fn noop() -> Self {
        Self {
            exit: false,
            set_target: SetTarget::Unchanged,
        }
    }

    pub fn exit() -> Self {
        Self {
            exit: true,
            set_target: SetTarget::Unchanged,
        }
    }

    pub fn update_target(addr: Option<SocketAddr>) -> Self {
        Self {
            exit: false,
            set_target: SetTarget::Update(addr),
        }
    }
}

pub enum SetTarget {
    Update(Option<SocketAddr>),
    Unchanged,
}

#[async_trait]
pub trait Handler<C>: Send + Sync
where
    C: Cipher + 'static,
{
    async fn run(
        &self,
        ptr: Arc<EventLayer<C>>,
        clients: &RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>,
        request_id: u32,
        matches: clap::ArgMatches,
    ) -> HandlerResult;
}
