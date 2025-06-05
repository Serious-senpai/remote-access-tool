use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use common::cipher::encryption::Cipher;
use common::payloads::custom::answer::{Answer, Response};
use common::payloads::custom::command::{Command, Request};
use common::payloads::custom::ping::Ping;
use common::payloads::custom::pong::Pong;
use common::payloads::disconnect::Disconnect;
use common::payloads::PayloadFormat;
use common::utils::{format_bytes, ConsoleTable};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{timeout, Duration};

use super::events::EventLayer;

pub const PROMPT: &str = "server>";

#[derive(Debug, Parser)]
#[command(
    disable_help_flag = true,
    name = PROMPT,
    long_about = "Remote Access Tool (RAT) server component",
    no_binary_name = true
)]
pub struct Internal {
    #[command(subcommand)]
    pub command: InternalCommand,
}

#[derive(Debug, Subcommand)]
pub enum InternalCommand {
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
pub enum InternalClientsCommand {
    /// List connected clients
    Ls,

    /// Disconnect a client
    Disconnect {
        /// The address of the client to disconnect
        addr: SocketAddr,
    },
}

impl InternalCommand {
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

    async fn expect_cd<C>(ptr: Arc<EventLayer<C>>, true_addr: SocketAddr, request_id: u32) -> String
    where
        C: Cipher + Clone + Send + Sync + 'static,
    {
        let mut receiver = ptr.subscribe();
        loop {
            if let Ok((addr, packet)) = receiver.recv().await {
                if addr == true_addr {
                    if let Ok(answer) = Answer::from_packet(&packet).await {
                        if answer.request_id() == request_id {
                            if let Response::Cd(path, message) = answer.answer() {
                                break format!("{}\n{}", path.to_string_lossy(), message);
                            }
                        }
                    }
                }
            }
        }
    }

    async fn expect_ls<C>(ptr: Arc<EventLayer<C>>, true_addr: SocketAddr, request_id: u32)
    where
        C: Cipher + Clone + Send + Sync + 'static,
    {
        let mut receiver = ptr.subscribe();
        loop {
            if let Ok((addr, packet)) = receiver.recv().await {
                if addr == true_addr {
                    if let Ok(answer) = Answer::from_packet(&packet).await {
                        if answer.request_id() == request_id {
                            if let Response::Ls(entries) = answer.answer() {
                                let mut table = ConsoleTable::new([
                                    "File Name".to_string(),
                                    "File Type".to_string(),
                                    "Created At".to_string(),
                                    "Modified At".to_string(),
                                    "Size (bytes)".to_string(),
                                ]);

                                for entry in entries {
                                    let (created_at, modified_at, formatted_size) = match &entry
                                        .metadata
                                    {
                                        Some(metadata) => {
                                            let created_at =
                                                DateTime::<Utc>::from(metadata.created_at)
                                                    .format("%Y-%m-%d %H:%M:%S")
                                                    .to_string();
                                            let modified_at =
                                                DateTime::<Utc>::from(metadata.modified_at)
                                                    .format("%Y-%m-%d %H:%M:%S")
                                                    .to_string();
                                            (created_at, modified_at, format_bytes(metadata.size))
                                        }
                                        None => (
                                            "N/A".to_string(),
                                            "N/A".to_string(),
                                            "N/A".to_string(),
                                        ),
                                    };
                                    table.add_row([
                                        entry.file_name.clone(),
                                        entry.file_type.clone(),
                                        created_at,
                                        modified_at,
                                        formatted_size,
                                    ]);
                                }

                                table.print();
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn expect_pwd<C>(
        ptr: Arc<EventLayer<C>>,
        true_addr: SocketAddr,
        request_id: u32,
    ) -> String
    where
        C: Cipher + Clone + Send + Sync + 'static,
    {
        let mut receiver = ptr.subscribe();
        loop {
            if let Ok((addr, packet)) = receiver.recv().await {
                if addr == true_addr {
                    if let Ok(answer) = Answer::from_packet(&packet).await {
                        if answer.request_id() == request_id {
                            if let Response::Pwd(path) = answer.answer() {
                                break path.to_string_lossy().into_owned();
                            }
                        }
                    }
                }
            }
        }
    }

    pub async fn execute<C>(
        &self,
        ptr: Arc<EventLayer<C>>,
        clients: &RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>,
        request_id: u32,
    ) -> bool
    where
        C: Cipher + Clone + Send + Sync + 'static,
    {
        match self {
            InternalCommand::Clients { command } => match command {
                InternalClientsCommand::Ls => {
                    match Ping::new(0).to_payload().await {
                        Ok(payload) => {
                            let mut wait = vec![];
                            {
                                let clients = clients.read().await;
                                for (addr, sender) in clients.iter() {
                                    wait.push((
                                        *addr,
                                        // Even though `expect_pong` may time out in the middle of stream reading (and thus
                                        // end up in a random position in the stream), this is still acceptable because it
                                        // is regarded as a timeout and the client will be disconnected afterwards.
                                        //
                                        // A slow RTT of ~5 seconds can be considered as a timeout, right? :)
                                        tokio::spawn(timeout(
                                            Duration::from_secs(5),
                                            Self::expect_pong::<C>(ptr.clone(), *addr, 0),
                                        )),
                                    ));

                                    let _ = sender.send(payload.clone());
                                }
                            }

                            let mut table = ConsoleTable::new([
                                "Address".to_string(),
                                "Version string".to_string(),
                            ]);
                            let disconnect = Disconnect::new(11, "Disconnected by server", "")
                                .to_payload()
                                .await
                                .ok();
                            let mut clients = clients.write().await;
                            for (addr, f) in wait {
                                match f.await {
                                    Ok(Ok(version)) => {
                                        table.add_row([addr.to_string(), version]);
                                    }
                                    _ => {
                                        if let Some(sender) = clients.remove(&addr) {
                                            if let Some(payload) = disconnect.clone() {
                                                tokio::spawn(async move {
                                                    let _ = sender.send(payload);
                                                });
                                            }
                                        }
                                    }
                                }
                            }

                            table.print();
                        }
                        Err(e) => {
                            eprintln!("Unable to create ping payload: {}", e);
                        }
                    };
                }
                InternalClientsCommand::Disconnect { addr } => {
                    let mut clients = clients.write().await;
                    match clients.remove(&addr) {
                        Some(sender) => {
                            if let Ok(payload) = Disconnect::new(11, "Disconnected by server", "")
                                .to_payload()
                                .await
                            {
                                let _ = sender.send(payload);
                            }
                        }
                        None => {
                            eprintln!("No client with address {}", addr);
                        }
                    }
                }
            },
            InternalCommand::Cd { addr, path } => {
                let clients = clients.read().await;
                match clients.get(&addr) {
                    Some(sender) => {
                        if let Ok(payload) = Command::new(request_id, Request::Cd(path.into()))
                            .to_payload()
                            .await
                        {
                            let task = tokio::spawn(Self::expect_cd::<C>(
                                ptr.clone(),
                                addr.clone(),
                                request_id,
                            ));

                            if sender.send(payload).is_ok() {
                                match task.await {
                                    Ok(path) => {
                                        println!("{}", path);
                                    }
                                    Err(e) => {
                                        eprintln!("{}", e);
                                    }
                                }

                                return false;
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
                let clients = clients.read().await;
                match clients.get(&addr) {
                    Some(sender) => {
                        if let Ok(payload) = Command::new(
                            request_id,
                            Request::Ls(path.clone().unwrap_or_else(|| PathBuf::from("."))),
                        )
                        .to_payload()
                        .await
                        {
                            let task = tokio::spawn(Self::expect_ls::<C>(
                                ptr.clone(),
                                addr.clone(),
                                request_id,
                            ));

                            if sender.send(payload).is_ok() {
                                let _ = task.await;
                                return false;
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
                let clients = clients.read().await;
                match clients.get(&addr) {
                    Some(sender) => {
                        if let Ok(payload) =
                            Command::new(request_id, Request::Pwd).to_payload().await
                        {
                            let task = tokio::spawn(Self::expect_pwd::<C>(
                                ptr.clone(),
                                addr.clone(),
                                request_id,
                            ));

                            if sender.send(payload).is_ok() {
                                match task.await {
                                    Ok(path) => {
                                        println!("{}", path);
                                    }
                                    Err(e) => {
                                        eprintln!("{}", e);
                                    }
                                }

                                return false;
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
                return true;
            }
        }

        false
    }
}
