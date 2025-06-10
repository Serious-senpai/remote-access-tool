use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::cipher::encryption::Cipher;
use common::cipher::hostkey::HostKeyAlgorithm;
use common::cipher::kex::KexAlgorithm;
use common::packets::Packet;
use common::payloads::custom::cancel::Cancel;
use common::payloads::custom::ping::Ping;
use common::payloads::custom::pong::Pong;
use common::payloads::custom::query::{Query, QueryType};
use common::payloads::custom::request::Request;
use common::payloads::custom::response::{ClientEntry, Response, ResponseType};
use common::payloads::disconnect::Disconnect;
use common::payloads::PayloadFormat;
use common::utils::wait_for;
use log::{error, info, warn};
use ssh_key::PrivateKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::{broadcast, Notify, RwLock};
use tokio::time::timeout;

use crate::layers::clients::ClientLayer;

#[derive(Debug)]
struct ClientLayerCtx<C>
where
    C: Cipher + 'static,
{
    pub is_admin: bool,
    // pub task: JoinHandle<()>,
    pub ptr: Arc<ClientLayer<C>>,
}

/// Packet aggregation layer
#[derive(Debug)]
pub struct AggregationLayer<C>
where
    C: Cipher + 'static,
{
    _listener: TcpListener,
    _host_key: Vec<u8>,
    _private_key: PrivateKey,

    /// Mapping from client addresses to their appropriate contexts.
    _clients: RwLock<HashMap<SocketAddr, ClientLayerCtx<C>>>,

    /// Clone this sender to new incoming clients so that they can send packets to this aggregation node.
    /// We can also subscribe to this sender to receive packets from all clients.
    _primordial_client_sender: broadcast::Sender<(SocketAddr, Packet<C>)>,

    _exit: Arc<Notify>,
}

impl<C> AggregationLayer<C>
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
        Self {
            _listener: listener,
            _host_key: host_key,
            _private_key: private_key,
            _clients: RwLock::new(HashMap::new()),
            _primordial_client_sender: primordial_client_sender,
            _exit: Arc::new(Notify::new()),
        }
    }

    async fn _handle_packet(self: Arc<Self>, origin: SocketAddr, packet: Packet<C>) {
        if let Ok(payload) = Disconnect::from_packet(&packet).await {
            info!(
                "Received disconnect packet from {}: {}",
                origin,
                payload.description()
            );

            let mut clients = self._clients.write().await;
            clients.remove(&origin);
        } else if let Ok(payload) = Request::from_packet(&packet).await {
            let error = |message| {
                Some(Response::error_and_log(
                    payload.request_id(),
                    origin,
                    payload.dest(),
                    message,
                ))
            };

            let clients = self._clients.read().await;
            let response = match clients.get(&origin) {
                Some(ctx) => {
                    if origin != payload.src() {
                        error(format!(
                            "Mismatch src field in request: expected {}, got {}",
                            origin,
                            payload.src()
                        ))
                    } else if ctx.is_admin {
                        match clients.get(&payload.dest()) {
                            Some(target) => {
                                if target.is_admin {
                                    error(format!(
                                        "Cannot forward request to admin client {}",
                                        payload.dest(),
                                    ))
                                } else {
                                    match target
                                        .ptr
                                        .send(&Request::new(
                                            payload.request_id(),
                                            origin,
                                            payload.dest(),
                                            payload.rtype().clone(),
                                        ))
                                        .await
                                    {
                                        Ok(_) => None,
                                        Err(e) => error(format!(
                                            "Unable to forward request to {}: {}",
                                            payload.dest(),
                                            e
                                        )),
                                    }
                                }
                            }
                            None => {
                                error(format!("Command target does not exist: {}", payload.dest(),))
                            }
                        }
                    } else {
                        error(format!("Client {} is not authenticated", origin))
                    }
                }
                None => {
                    error!("Received request from unknown address {}", origin);
                    None
                }
            };

            if let Some(response) = response {
                if let Some(ctx) = clients.get(&origin) {
                    let _ = ctx.ptr.send(&response).await;
                }
            }
        } else if let Ok(payload) = Response::from_packet(&packet).await {
            let clients = self._clients.read().await;
            if payload.dest() == origin {
                match clients.get(&payload.src()) {
                    Some(ctx) => {
                        let _ = ctx.ptr.send(&payload).await;
                    }
                    None => {
                        warn!(
                            "Cannot forward response to {}. Maybe client have disconnected?",
                            payload.src()
                        );
                    }
                }
            }
        } else if let Ok(payload) = Cancel::from_packet(&packet).await {
            for (&addr, ctx) in self._clients.read().await.iter() {
                if addr != origin {
                    let _ = ctx.ptr.send(&payload).await;
                }
            }
        } else if let Ok(payload) = Query::from_packet(&packet).await {
            match payload.qtype() {
                QueryType::Authenticate { rkey } => {
                    info!("Received authentication query from {}", origin);

                    let mut success = false;
                    let response = match self._private_key.to_bytes() {
                        Ok(bytes) => {
                            if *bytes == *rkey {
                                success = true;
                                Response::response_query(&payload, ResponseType::Success)
                            } else {
                                Response::error_and_log(
                                    payload.request_id(),
                                    origin,
                                    origin,
                                    "Invalid private key",
                                )
                            }
                        }
                        Err(e) => Response::error_and_log(
                            payload.request_id(),
                            origin,
                            origin,
                            format!("Failed to convert private key to bytes: {}", e),
                        ),
                    };

                    let mut clients = self._clients.write().await;
                    if let Some(ctx) = clients.get_mut(&origin) {
                        ctx.is_admin = success;
                        let _ = ctx.ptr.send(&response).await;
                    }
                }
                QueryType::ClientLs => {
                    let mut clients = self._clients.write().await;
                    let mut tasks = vec![];
                    let ping = Ping::new(0);

                    for (&c_addr, ctx) in clients.iter() {
                        let mut receiver = self._primordial_client_sender.subscribe();
                        let ping = ping.clone();

                        let _ = ctx.ptr.send(&ping).await;
                        tasks.push(tokio::spawn(timeout(Duration::from_secs(5), async move {
                            wait_for(&mut receiver, async |(r_addr, packet)| {
                                if c_addr == r_addr {
                                    if let Ok(pong) = Pong::from_packet(&packet).await {
                                        if pong.data() == 1 {
                                            return Some(r_addr);
                                        }
                                    }
                                }

                                None
                            })
                            .await
                        })));
                    }

                    let mut alive = HashSet::new();
                    for task in tasks {
                        if let Ok(Ok(addr)) = task.await {
                            alive.insert(addr);
                        }
                    }

                    clients.retain(|k, _| alive.contains(k));

                    if let Some(ctx) = clients.get(&origin) {
                        let _ = ctx
                            .ptr
                            .send(&Response::response_query(
                                &payload,
                                ResponseType::ClientLs {
                                    clients: clients
                                        .iter()
                                        .map(|(addr, ctx)| {
                                            ClientEntry {
                                                addr: *addr,
                                                version: ctx.ptr.version.clone(), // Placeholder version
                                                is_admin: ctx.is_admin,
                                            }
                                        })
                                        .collect(),
                                },
                            ))
                            .await;
                    }
                }
                QueryType::ClientDisconnect { addr } => {
                    let clients = self._clients.read().await;
                    let response = match clients.get(addr) {
                        Some(target) => {
                            let _ = target
                                .ptr
                                .send(&Disconnect::new(
                                    11,
                                    format!("Disconnected by {}", origin),
                                    "",
                                ))
                                .await;
                            Response::response_query(&payload, ResponseType::Success)
                        }
                        None => Response::response_query(
                            &payload,
                            ResponseType::Error {
                                message: format!("Client {} does not exist", addr),
                            },
                        ),
                    };

                    if let Some(ctx) = clients.get(&origin) {
                        let _ = ctx.ptr.send(&response).await;
                    }
                }
            }
        }
    }

    async fn _handle_connection<K, H>(self: Arc<Self>, socket: TcpStream, addr: SocketAddr)
    where
        K: KexAlgorithm,
        H: HostKeyAlgorithm,
    {
        match ClientLayer::<C>::accept_connection::<K, H>(
            socket,
            addr,
            self._host_key.clone(),
            self._private_key.clone(),
        )
        .await
        {
            Ok(client) => {
                let client = Arc::new(client);
                let c_sender = self._primordial_client_sender.clone();

                let c_client = client.clone();
                tokio::spawn(c_client.listen_loop(c_sender));

                let mut clients = self._clients.write().await;
                clients.insert(
                    addr,
                    ClientLayerCtx {
                        is_admin: false,
                        ptr: client,
                    },
                );
            }
            Err(e) => {
                error!("Failed to exchange keys with new client {}: {}", addr, e);
            }
        }
    }

    async fn _poll_packets(self: Arc<Self>) {
        let mut receiver = self._primordial_client_sender.subscribe();

        let mut tasks = VecDeque::new();
        let task_complete = Arc::new(Notify::new());

        loop {
            tokio::select! {
                _ = self._exit.notified() => {
                    break;
                }
                Ok((origin, packet)) = receiver.recv() => {
                    let ptr = self.clone();

                    let completer = task_complete.clone();
                    let task = tokio::spawn(async move{
                        ptr._handle_packet(origin, packet).await;
                        completer.notify_waiters();
                    });
                    tasks.push_back(task);
                }
                _ = task_complete.notified() => {
                    while let Some(task) = tasks.front() {
                        if task.is_finished() {
                            tasks.pop_front();
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        for task in tasks {
            let _ = task.await;
        }
    }

    async fn _poll_new_connections<K, H>(self: Arc<Self>)
    where
        K: KexAlgorithm,
        H: HostKeyAlgorithm,
    {
        let mut tasks = VecDeque::new();
        let task_complete = Arc::new(Notify::new());

        loop {
            tokio::select! {
                _ = self._exit.notified() => {
                    break;
                }
                Ok((socket, addr)) = self._listener.accept() => {
                    let ptr = self.clone();

                    let completer = task_complete.clone();
                    let task = tokio::spawn(async move {
                        ptr._handle_connection::<K, H>(socket, addr).await;
                        completer.notify_waiters();
                    });
                    tasks.push_back(task);
                }
                _ = task_complete.notified() => {
                    while let Some(task) = tasks.front() {
                        if task.is_finished() {
                            tasks.pop_front();
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        for task in tasks {
            let _ = task.await;
        }
    }

    pub async fn listen_loop<K, H>(self: Arc<Self>)
    where
        K: KexAlgorithm + 'static,
        H: HostKeyAlgorithm + 'static,
    {
        let ptr = self.clone();
        let poll_packets = tokio::spawn(ptr._poll_packets());

        let ptr = self.clone();
        let poll_new_connections = tokio::spawn(ptr._poll_new_connections::<K, H>());

        let _ = signal::ctrl_c().await;
        self._exit.notify_waiters();
        info!("Received Ctrl+C signal, shutting down...");

        let (r1, r2) = tokio::join!(poll_packets, poll_new_connections);
        if let Err(e) = r1 {
            error!(
                "Error while shutting down packets polling in aggregation layer: {}",
                e
            );
        }
        if let Err(e) = r2 {
            error!(
                "Error while shutting down connections polling in aggregation layer: {}",
                e
            );
        }

        let payload = Disconnect::new(11, "Server is shutting down", "");
        for (_, ctx) in self._clients.read().await.iter() {
            let _ = ctx.ptr.send(&payload).await;
        }
    }
}
