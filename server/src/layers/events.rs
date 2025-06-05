use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use common::cipher::encryption::Cipher;
use common::cipher::hostkey::HostKeyAlgorithm;
use common::cipher::kex::KexAlgorithm;
use common::packets::Packet;
use log::error;
use rustyline::DefaultEditor;
use ssh_key::PrivateKey;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Notify, RwLock};
use tokio::task::spawn_blocking;
use tokio::time::{timeout, Duration};

use super::clients::ClientLayer;
use super::handlers::{Internal, PROMPT};

type _PacketInfo<C> = (SocketAddr, Packet<C>);

/// Event-packet logic layer
///
/// Cardinality: 1
#[derive(Debug)]
pub struct EventLayer<C>
where
    C: Cipher,
{
    _listener: TcpListener,
    _host_key: Vec<u8>,
    _private_key: PrivateKey,

    /// Mapping from client addresses to their appropriate senders.
    /// We can use these senders to send packets to a specific client.
    _clients: RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>,

    /// Clone this sender to new incoming clients so that they can send packets to this event node.
    /// We can also subscribe to this sender to receive packets from all clients.
    _primordial_client_sender: broadcast::Sender<_PacketInfo<C>>,
}

impl<C> EventLayer<C>
where
    C: Cipher + Clone + Send + Sync + 'static,
{
    pub fn new(
        listener: TcpListener,
        host_key: Vec<u8>,
        private_key: PrivateKey,
        capacity: usize,
    ) -> Self {
        let (primordial_client_sender, _) = broadcast::channel(capacity);
        EventLayer {
            _listener: listener,
            _host_key: host_key,
            _private_key: private_key,
            _clients: RwLock::new(HashMap::new()),
            _primordial_client_sender: primordial_client_sender,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<_PacketInfo<C>> {
        self._primordial_client_sender.subscribe()
    }

    async fn interactive_loop(self: Arc<Self>, notify_on_exit: Arc<Notify>) {
        let mut request_id = 0;
        match DefaultEditor::new() {
            Ok(mut editor) => loop {
                let task = spawn_blocking(move || {
                    let mut e = editor;
                    let line = e.readline(PROMPT);
                    (e, line)
                });
                let line = match task.await {
                    Ok((e, line)) => {
                        editor = e;
                        match line {
                            Ok(l) => l,
                            Err(e) => {
                                eprintln!("{}", e);
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        break;
                    }
                };

                let tokens = match shlex::split(&line) {
                    Some(tokens) => tokens,
                    None => {
                        eprintln!("Invalid command syntax");
                        continue;
                    }
                };

                let _ = editor.add_history_entry(&line);
                let command = match Internal::try_parse_from(tokens) {
                    Ok(arguments) => arguments,
                    Err(e) => {
                        let _ = e.print();
                        continue;
                    }
                };

                match timeout(
                    Duration::from_secs(10),
                    command
                        .command
                        .execute(self.clone(), &self._clients, request_id),
                )
                .await
                {
                    Ok(exit) => {
                        if exit {
                            break;
                        }
                    }
                    Err(error) => eprintln!("Command timed out: {}", error),
                }

                request_id = request_id.wrapping_add(1);
            },
            Err(e) => {
                eprintln!("Unable to start interactive mode: {}", e);
            }
        }

        notify_on_exit.notify_one();
    }

    pub async fn listen_loop<K, H>(self) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        K: KexAlgorithm,
        H: HostKeyAlgorithm,
    {
        let ptr = Arc::new(self);
        let notify_on_exit = Arc::new(Notify::new());

        tokio::spawn(ptr.clone().interactive_loop(notify_on_exit.clone()));

        loop {
            tokio::select! {
                pair = ptr._listener.accept() => {
                    match pair {
                        Ok((socket, addr)) => {
                            match ClientLayer::<C>::accept_connection::<K, H>(
                                socket,
                                addr,
                                ptr._host_key.clone(),
                                ptr._private_key.clone(),
                            )
                            .await
                            {
                                Ok(client) => {
                                    let c_sender = ptr._primordial_client_sender.clone();
                                    let (e_sender, c_receiver) = mpsc::unbounded_channel();
                                    tokio::spawn(client.listen_loop(c_sender, c_receiver));

                                    let mut clients = ptr._clients.write().await;
                                    clients.insert(addr, e_sender);
                                }
                                Err(e) => {
                                    error!("Failed to exchange keys with new client {}: {}", addr, e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to accept new TCP connection: {}", e);
                        }
                    }
                }
                _ = notify_on_exit.notified() => {
                    break Ok(());
                }
            }
        }
    }
}
