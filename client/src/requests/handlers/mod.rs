pub mod cd;
pub mod clear;
pub mod client;
pub mod download;
pub mod exit;
pub mod kill;
pub mod ls;
pub mod mkdir;
pub mod ps;
pub mod pwd;
pub mod rm;
pub mod target;

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;

use crate::BroadcastLayer;

pub struct HandlerResult {
    pub exit: bool,
    pub clear: bool,
    pub set_target: SetTarget,
}

impl HandlerResult {
    pub fn noop() -> Self {
        Self {
            exit: false,
            clear: false,
            set_target: SetTarget::Unchanged,
        }
    }

    pub fn exit() -> Self {
        Self {
            exit: true,
            clear: false,
            set_target: SetTarget::Unchanged,
        }
    }

    pub fn clear() -> Self {
        Self {
            exit: false,
            clear: true,
            set_target: SetTarget::Unchanged,
        }
    }

    pub fn update_target(addr: Option<SocketAddr>) -> Self {
        Self {
            exit: false,
            clear: false,
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
    C: Cipher,
{
    async fn run(
        &self,
        broadcast: Arc<BroadcastLayer<C>>,
        request_id: u32,
        local_addr: SocketAddr,
        matches: clap::ArgMatches,
    ) -> HandlerResult;
}
