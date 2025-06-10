use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use common::cipher::encryption::Cipher;
use common::packets::Packet;
use common::payloads::custom::ping::Ping;
use common::payloads::custom::pong::Pong;
use common::payloads::disconnect::Disconnect;
use common::payloads::PayloadFormat;
use common::ssh::SSH;
use log::{error, info};
use tokio::sync::{broadcast, Notify};

/// Packet broadcasting layer
#[derive(Debug)]
pub struct BroadcastLayer<C>
where
    C: Cipher,
{
    _ssh: SSH<C>,
    _sender: broadcast::Sender<Packet<C>>,
    _exit: Arc<Notify>,
}

impl<C> BroadcastLayer<C>
where
    C: Cipher + 'static,
{
    pub fn new(ssh: SSH<C>, capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            _ssh: ssh,
            _sender: sender,
            _exit: Arc::new(Notify::new()),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self._ssh.local_addr()
    }

    pub async fn wait_until_exit(&self) {
        self._exit.notified().await;
    }

    pub async fn exit(&self) {
        self._exit.notify_waiters();
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Packet<C>> {
        self._sender.subscribe()
    }

    pub async fn send<P>(&self, payload: &P) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        P: PayloadFormat + 'static,
    {
        self._ssh.write_payload(payload).await?;
        Ok(())
    }

    async fn _poll_packets(self: Arc<Self>) -> Result<(), Box<dyn Error + Send + Sync>> {
        loop {
            tokio::select! {
                _ = self._exit.notified() => {
                    break
                }
                _ = self._ssh.peek() => {
                    let packet = match self._ssh.read_packet().await {
                        Ok(val) => val,
                        Err(e) => {
                            error!("Unable to read packet: {}", e);
                            break;
                        }
                    };

                    if let Ok(payload) = Disconnect::from_packet(&packet).await {
                        info!(
                            "Disconnecting: {} (code: {})",
                            payload.description(),
                            payload.reason_code()
                        );

                        break;
                    } else if let Ok(payload) = Ping::from_packet(&packet).await {
                        if let Err(e) = async {
                            let response = Pong::from_ping(&payload);
                            self.send(&response).await?;

                            Ok::<(), Box<dyn Error + Send + Sync>>(())
                        }
                        .await
                        {
                            error!("Failed to play ping-pong game: {}", e)
                        }
                    } else if let Err(e) = self._sender.send(packet) {
                        error!(
                            "Received a packet, but unable to notify higher levels: {}",
                            e
                        );
                    }
                }
            }
        }

        self.exit().await;
        Ok(())
    }

    pub async fn listen_loop(self: Arc<Self>) {
        let ptr = self.clone();
        if let Err(e) = ptr._poll_packets().await {
            error!("Error polling packets: {}", e);
        }

        let disconnect = Disconnect::new(11, "Client shutdown", "");
        if let Err(e) = self.send(&disconnect).await {
            error!("Failed to send disconnect payload: {}", e);
        }
    }
}
