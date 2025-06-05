use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use common::cipher::encryption::Cipher;
use common::cipher::hostkey::HostKeyAlgorithm;
use common::cipher::kex::KexAlgorithm;
use common::packets::Packet;
use common::payloads::custom::cwd::Cwd;
use common::payloads::custom::ls::ListDir;
use common::payloads::custom::ping::Ping;
use common::payloads::custom::pong::Pong;
use common::payloads::custom::request::{Command, Request};
use common::payloads::disconnect::Disconnect;
use common::payloads::PayloadFormat;
use common::utils::{format_bytes, ConsoleTable};
use log::error;
use rustyline::DefaultEditor;
use ssh_key::PrivateKey;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Notify, RwLock};
use tokio::task::spawn_blocking;
use tokio::time::{timeout, Duration};

use super::clients::ClientLayer;

const PROMPT: &str = "server>";

#[derive(Debug, Parser)]
#[command(
    disable_help_flag = true,
    name = PROMPT,
    long_about = "Remote Access Tool (RAT) server component",
    no_binary_name = true
)]
struct Internal {
    #[command(subcommand)]
    pub command: InternalCommand,
}

#[derive(Debug, Subcommand)]
enum InternalCommand {
    /// Manage connected clients
    Clients {
        #[command(subcommand)]
        command: InternalClientsCommand,
    },

    /// Change the working directory in the client side
    Cd {
        /// The address of the client to change directory for
        addr: SocketAddr,
        /// The new working directory path
        path: PathBuf,
    },

    /// List information about a directory in the client side
    Ls {
        /// The address of the client to query
        addr: SocketAddr,

        /// The path to the directory to list (default to current working directory)
        path: Option<PathBuf>,
    },

    /// Print working directory in the client side
    Pwd {
        /// The address of the client to query
        addr: SocketAddr,
    },

    /// Shut down the server
    Exit,
}

#[derive(Debug, Subcommand)]
enum InternalClientsCommand {
    /// List connected clients
    Ls,

    /// Disconnect a client
    Disconnect {
        /// The address of the client to disconnect
        addr: SocketAddr,
    },
}

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

    fn subscribe(&self) -> broadcast::Receiver<_PacketInfo<C>> {
        self._primordial_client_sender.subscribe()
    }

    async fn wait_for(&self, check: impl Fn(&_PacketInfo<C>) -> bool) -> _PacketInfo<C> {
        let mut receiver = self.subscribe();
        loop {
            if let Ok(packet) = receiver.recv().await {
                if check(&packet) {
                    return packet;
                }
            }
        }
    }

    async fn interactive_loop(self: Arc<Self>, notify_on_exit: Arc<Notify>) {
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

                match command.command {
                    InternalCommand::Clients { command } => match command {
                        InternalClientsCommand::Ls => {
                            async fn expect_pong<C>(
                                ptr: Arc<EventLayer<C>>,
                                true_addr: SocketAddr,
                                true_value: u8,
                            ) -> String
                            where
                                C: Cipher + Clone + Send + Sync + 'static,
                            {
                                let mut receiver = ptr.subscribe();
                                loop {
                                    if let Ok((addr, packet)) = receiver.recv().await {
                                        if addr == true_addr {
                                            if let Ok(pong) = Pong::from_packet(&packet).await {
                                                if pong.data() == true_value {
                                                    return pong.version().to_string();
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            let payload = match Ping::new(0).to_payload().await {
                                Ok(p) => p,
                                Err(e) => {
                                    eprintln!("Unable to create ping payload: {}", e);
                                    continue;
                                }
                            };

                            let mut wait = vec![];
                            {
                                let clients = self._clients.read().await;
                                for (addr, sender) in clients.iter() {
                                    wait.push((
                                        addr.clone(),
                                        tokio::spawn(timeout(
                                            Duration::from_secs(5),
                                            expect_pong::<C>(self.clone(), addr.clone(), 0),
                                        )),
                                    ));

                                    let _ = sender.send(payload.clone());
                                }
                            }

                            let mut table = ConsoleTable::new([
                                "Address".to_string(),
                                "Version string".to_string(),
                            ]);
                            let mut clients = self._clients.write().await;
                            for (addr, f) in wait {
                                match f.await {
                                    Ok(Ok(version)) => {
                                        table.add_row([addr.to_string(), version]);
                                    }
                                    _ => {
                                        clients.remove(&addr);
                                    }
                                }
                            }

                            table.print();
                        }
                        InternalClientsCommand::Disconnect { addr } => {
                            let mut clients = self._clients.write().await;
                            if let Some(sender) = clients.remove(&addr) {
                                if let Ok(payload) =
                                    Disconnect::new(11, "Disconnected by server", "")
                                        .to_payload()
                                        .await
                                {
                                    let _ = sender.send(payload);
                                }
                            } else {
                                eprintln!("No client with address {}", addr);
                            }
                        }
                    },
                    InternalCommand::Cd { addr, path } => {
                        let clients = self._clients.read().await;
                        match clients.get(&addr) {
                            Some(sender) => {
                                if let Ok(payload) =
                                    Request::new(Command::Cd(path)).to_payload().await
                                {
                                    if let Ok(_) = sender.send(payload) {
                                        let (_, packet) = self
                                            .wait_for(|(r_addr, r_packet)| {
                                                r_addr == &addr
                                                    && r_packet.peek_opcode() == Some(Cwd::OPCODE)
                                            })
                                            .await;

                                        if let Ok(cwd) = Cwd::from_packet(&packet).await {
                                            println!("{}", cwd.cwd().to_string_lossy());
                                        }

                                        continue;
                                    }
                                }

                                eprintln!("Unable to send packet to {}", addr);
                            }
                            None => {
                                eprintln!("No client with address {}", addr);
                            }
                        }
                    }
                    InternalCommand::Pwd { addr } => {
                        let clients = self._clients.read().await;
                        match clients.get(&addr) {
                            Some(sender) => {
                                if let Ok(payload) = Request::new(Command::Pwd).to_payload().await {
                                    if let Ok(_) = sender.send(payload) {
                                        let (_, packet) = self
                                            .wait_for(|(r_addr, r_packet)| {
                                                r_addr == &addr
                                                    && r_packet.peek_opcode() == Some(Cwd::OPCODE)
                                            })
                                            .await;

                                        if let Ok(cwd) = Cwd::from_packet(&packet).await {
                                            println!("{}", cwd.cwd().to_string_lossy());
                                        }

                                        continue;
                                    }
                                }

                                eprintln!("Unable to send packet to {}", addr);
                            }
                            None => {
                                eprintln!("No client with address {}", addr);
                            }
                        }
                    }
                    InternalCommand::Ls { addr, path } => {
                        let clients = self._clients.read().await;
                        match clients.get(&addr) {
                            Some(sender) => {
                                if let Ok(payload) =
                                    Request::new(Command::Ls(path)).to_payload().await
                                {
                                    if let Ok(_) = sender.send(payload) {
                                        let (_, packet) = self
                                            .wait_for(|(r_addr, r_packet)| {
                                                r_addr == &addr
                                                    && r_packet.peek_opcode()
                                                        == Some(ListDir::OPCODE)
                                            })
                                            .await;

                                        if let Ok(ls) = ListDir::from_packet(&packet).await {
                                            let mut table = ConsoleTable::new([
                                                "File Name".to_string(),
                                                "File Type".to_string(),
                                                "Created At".to_string(),
                                                "Modified At".to_string(),
                                                "Size (bytes)".to_string(),
                                            ]);

                                            for entry in ls.entries() {
                                                let created_at =
                                                    DateTime::<Utc>::from(entry.created_at)
                                                        .format("%Y-%m-%d %H:%M:%S")
                                                        .to_string();
                                                let modified_at =
                                                    DateTime::<Utc>::from(entry.modified_at)
                                                        .format("%Y-%m-%d %H:%M:%S")
                                                        .to_string();
                                                table.add_row([
                                                    entry.file_name.clone(),
                                                    entry.file_type.clone(),
                                                    created_at,
                                                    modified_at,
                                                    format_bytes(entry.size),
                                                ]);
                                            }

                                            table.print();
                                        }

                                        continue;
                                    }
                                }

                                eprintln!("Unable to send packet to {}", addr);
                            }
                            None => {
                                eprintln!("No client with address {}", addr);
                            }
                        }
                    }
                    InternalCommand::Exit => {
                        break;
                    }
                }
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
