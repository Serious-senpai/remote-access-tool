use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use common::cipher::encryption::Cipher;
use common::cipher::hostkey::HostKeyAlgorithm;
use common::cipher::kex::KexAlgorithm;
use common::packets::Packet;
use common::payloads::custom::command::{Command, Request};
use common::payloads::disconnect::Disconnect;
use common::payloads::PayloadFormat;
use log::{debug, error};
use rustyline::DefaultEditor;
use ssh_key::PrivateKey;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Mutex, Notify, RwLock};
use tokio::task::spawn_blocking;
use tokio::{select, signal};

use super::clients::ClientLayer;
use super::commands::CommandBuilder;

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
    _primordial_client_sender: broadcast::Sender<(SocketAddr, Packet<C>)>,
}

impl<C> EventLayer<C>
where
    C: Cipher + 'static,
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

    pub fn subscribe(&self) -> broadcast::Receiver<(SocketAddr, Packet<C>)> {
        self._primordial_client_sender.subscribe()
    }

    pub async fn wait_for<T, R>(self: Arc<Self>, execute: impl Fn(SocketAddr, Packet<C>) -> T) -> R
    where
        T: Future<Output = Option<R>>,
    {
        let mut receiver = self.subscribe();
        loop {
            if let Ok((addr, packet)) = receiver.recv().await {
                if let Some(result) = execute(addr, packet).await {
                    break result;
                }
            }
        }
    }

    async fn interactive_loop(self: Arc<Self>, notify_on_exit: Arc<Notify>) {
        let mut request_id = 0;
        let mut command_builder = CommandBuilder::new();
        match DefaultEditor::new() {
            Ok(mut editor) => loop {
                let prompt = format!("\n{}", command_builder.prompt());
                let task = spawn_blocking(move || {
                    let mut e = editor;
                    let line = e.readline(&prompt);
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

                if line.trim().is_empty() {
                    continue;
                }

                let tokens = match shlex::split(&line) {
                    Some(tokens) => tokens,
                    None => {
                        eprintln!("Invalid command syntax");
                        continue;
                    }
                };

                let _ = editor.add_history_entry(&line);
                let matches = match command_builder.build_command().try_get_matches_from(tokens) {
                    Ok(matches) => matches,
                    Err(e) => {
                        let _ = e.print();
                        continue;
                    }
                };

                // Place a lock here to avoid dirty write (very rare, but not impossible)
                let abortable = Arc::new(Mutex::new(()));
                let abortable_cloned = abortable.clone();

                let ptr = self.clone();
                let signal_handler = tokio::spawn(async move {
                    let _ = signal::ctrl_c().await;
                    let _ = abortable_cloned.lock().await;
                    match Command::new(!request_id, Request::Cancel(request_id))
                        .to_payload()
                        .await
                    {
                        Ok(payload) => {
                            for (_, sender) in ptr._clients.read().await.iter() {
                                let _ = sender.send(payload.clone());
                            }
                        }
                        Err(e) => {
                            eprintln!("Unable to create cancel request: {}", e);
                        }
                    }
                });

                let exit = command_builder
                    .execute(self.clone(), &self._clients, request_id, matches)
                    .await;

                let _ = abortable.lock().await;
                signal_handler.abort();
                if exit {
                    break;
                }

                request_id = request_id.wrapping_add(1);
            },
            Err(e) => {
                eprintln!("Unable to start interactive mode: {}", e);
            }
        }

        // Wait for all tasks to clean up
        for _ in 0..5 {
            tokio::task::yield_now().await;
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

        let ptr_cloned = ptr.clone();
        tokio::spawn(async move {
            let mut receiver = ptr_cloned.subscribe();
            while let Ok((addr, packet)) = receiver.recv().await {
                if let Ok(payload) = Disconnect::from_packet(&packet).await {
                    debug!(
                        "Received disconnect packet from {}: {}",
                        addr,
                        payload.description()
                    );

                    let mut clients = ptr_cloned._clients.write().await;
                    clients.remove(&addr);
                }
            }
        });

        loop {
            select! {
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
