mod cli;
mod ipc;

use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;

use clap::error::{DefaultFormatter, ErrorFormatter};
use clap::{CommandFactory, Parser};
use cli::{Internal, InternalClientsCommand, InternalCommand};
use common::cipher::encryption::chacha20_poly1305::ChaCha20Poly1305;
use common::cipher::encryption::none::NoneCipher;
use common::cipher::encryption::CipherCtx;
use common::cipher::hostkey::rsa_sha2_512::RsaSha2512;
use common::cipher::hostkey::{read_host_key, HostKeyAlgorithm};
use common::cipher::kex::curve25519_sha256::Curve25519Sha256;
use common::cipher::kex::KexAlgorithm;
use common::config;
use common::payloads::custom::command::Command;
use common::payloads::disconnect::Disconnect;
use common::payloads::kex_ecdh_init::KexEcdhInit;
use common::payloads::kex_ecdh_reply::KexEcdhReply;
use common::payloads::kexinit::KexInit;
use common::payloads::newkeys::NewKeys;
use common::payloads::PayloadFormat;
use common::ssh::SSH;
use common::utils::write_string_vec;
use env_logger::Target;
use log::{debug, error};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{broadcast, mpsc, Mutex};

use ipc::{Action, ClientSent, ClientSentData, ServerSent};

struct RequestHandler {
    id: u32,
    stream: TcpStream,
    host_key: Vec<u8>,
    private_key: PrivateKey,
    client_sender: mpsc::UnboundedSender<ClientSent>,
    client_receiver: broadcast::Receiver<ServerSent>,
}

struct InteractiveHandler {
    server_sender: broadcast::Sender<ServerSent>,
    server_receiver: mpsc::UnboundedReceiver<ClientSent>,
}

async fn process(mut packed: RequestHandler) -> Result<(), Box<dyn Error>> {
    let mut ssh = SSH::<NoneCipher>::new(packed.stream, CipherCtx::DUMMY, CipherCtx::DUMMY);
    ssh.write_version_string(config::SSH_ID_STRING).await?;
    let client_id_string = ssh.read_version_string(true).await?;

    let server_kexinit_packet = ssh.write_payload(&KexInit::new()).await?;
    let client_kexinit_packet = &ssh.read_packet().await?;
    // TODO: Check supported algorithms

    let temp = ssh.read_packet().await?;
    let temp = KexEcdhInit::from_packet(&temp).await?;
    let client_ukey = temp.public_key();

    let key_pair = Curve25519Sha256::new("");
    let shared_secret =
        Curve25519Sha256::shared_secret(key_pair.private_seed.to_vec(), client_ukey.to_vec())?;

    let mut server_host_key_payload = vec![];
    write_string_vec(&mut server_host_key_payload, b"ssh-rsa").await;
    AsyncWriteExt::write_all(&mut server_host_key_payload, &packed.host_key).await?;

    let exchange_hash = Curve25519Sha256::exchange_hash(
        client_id_string.as_bytes(),
        config::SSH_ID_STRING.as_bytes(),
        &client_kexinit_packet.payload,
        &server_kexinit_packet.payload,
        &server_host_key_payload,
        client_ukey,
        &key_pair.public_key,
        &shared_secret,
    )
    .await;

    let signature = match packed.private_key.key_data() {
        ssh_key::private::KeypairData::Rsa(keypair) => {
            RsaSha2512::sign("rsa-sha2-512", &exchange_hash, keypair).await?
        }
        _ => unimplemented!(),
    };
    ssh.write_payload(
        &KexEcdhReply::new(
            "ssh-rsa".to_string(),
            packed.host_key,
            key_pair.public_key.to_vec(),
            "rsa-sha2-512".to_string(),
            signature,
        )
        .await,
    )
    .await?;

    ssh.write_payload(&NewKeys {}).await?;
    let temp = ssh.read_packet().await?;
    NewKeys::from_packet(&temp).await?;

    let session_id = &exchange_hash;
    let mut ssh = ssh
        .switch_encryption::<Curve25519Sha256, ChaCha20Poly1305, true>(
            &shared_secret,
            &exchange_hash,
            session_id,
        )
        .await?;

    if let Err(e) = packed.client_sender.send(ClientSent::new(
        packed.id,
        None,
        ClientSentData::ClientConnected {
            version: client_id_string,
        },
    )) {
        error!(
            "Successfully connected to client {}, but internal state was not updated: {}",
            packed.id, e
        );
    }

    loop {
        if let Ok(execution) = packed.client_receiver.recv().await {
            if execution.client_id() == packed.id {
                match execution.action() {
                    Action::Execute { command } => {
                        ssh.write_payload(&Command::new(packed.id, command)).await?;
                    }
                    Action::Disconnect => {
                        ssh.write_payload(&Disconnect::new(11, "Disconnected by server", "en"))
                            .await?;
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn interactive(packed: InteractiveHandler) -> Result<(), Box<dyn Error>> {
    let mut stdin = tokio::io::stdin();
    let mut request_id = 0;

    let clients = Arc::new(Mutex::new(HashMap::new()));

    async fn update_state(
        clients: Arc<Mutex<HashMap<u32, String>>>,
        mut server_receiver: mpsc::UnboundedReceiver<ClientSent>,
    ) {
        while let Some(update) = server_receiver.recv().await {
            match update.data() {
                ClientSentData::ClientConnected { version } => {
                    let mut clients = clients.lock().await;
                    clients.insert(update.client_id(), version.clone());
                }
                ClientSentData::ClientDisconnected => {
                    let mut clients = clients.lock().await;
                    clients.remove(&update.client_id());
                }
            }
        }
    }
    tokio::spawn(update_state(clients.clone(), packed.server_receiver));

    loop {
        print!("server>");
        std::io::stdout().flush()?;

        let mut buffer = String::new();
        loop {
            let c = stdin.read_u8().await?;
            if c == b'\n' || c == b'\r' {
                break;
            }

            buffer.push(c as char);
        }

        let tokens = if let Some(tokens) = shlex::split(&buffer) {
            tokens
        } else {
            eprintln!("Invalid command syntax");
            continue;
        };

        match Internal::try_parse_from(tokens) {
            Ok(arguments) => match arguments.command {
                InternalCommand::Clients { command } => match command {
                    InternalClientsCommand::List => {
                        let clients = clients.lock().await;
                        println!("Clients\tVersion string");
                        for (id, version) in clients.iter() {
                            println!("{}\t{}", id, version);
                        }
                    }
                    InternalClientsCommand::Disconnect { id } => {
                        let clients = clients.lock().await;
                        if !clients.contains_key(&id) {
                            eprintln!("Invalid client ID {}", id);
                            continue;
                        }

                        if let Err(e) = packed.server_sender.send(ServerSent::new(
                            id,
                            request_id,
                            Action::Disconnect,
                        )) {
                            eprintln!("Failed to send execution request: {}", e);
                        }

                        request_id = request_id.wrapping_add(1);
                    }
                },

                InternalCommand::Exit => {
                    break;
                }
            },
            Err(error) => {
                let _ = error.print();
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = cli::Arguments::parse();

    let mut log = colog::default_builder();
    log.filter_level(log::LevelFilter::Debug);
    log.target(Target::Pipe(Box::new(File::create(arguments.log_file)?)));
    log.init();

    let (ukey, rkey) = read_host_key(&arguments.host_key_file).await?;
    let listener = TcpListener::bind(("0.0.0.0", arguments.port)).await?;

    let (server_sender, _) = broadcast::channel(100);
    let (client_sender, server_receiver) = mpsc::unbounded_channel();

    let server_sender_cloned = server_sender.clone();
    select! {
        _ = async move {
            let packed = InteractiveHandler {
                server_sender,
                server_receiver,
            };

            if let Err(e) = interactive(packed).await {
                error!("Interactive session completed with error {}", e);
            }
        } => {}
        _ = async move {
            let mut id = 0;
            loop {
                if let Ok((socket, addr)) = listener.accept().await {
                    debug!("New client ({}): {}", id, addr);

                    let packed = RequestHandler {
                        id,
                        stream: socket,
                        host_key: ukey.clone(),
                        private_key: rkey.clone(),
                        client_sender: client_sender.clone(),
                        client_receiver: server_sender_cloned.subscribe(),
                    };
                    tokio::spawn(async move {
                        let id = packed.id;
                        if let Err(e) = process(packed).await {
                            error!("Client {} completed with error {}", id, e);
                        }
                    });

                    id = id.wrapping_add(1);
                }
            }
        } => {}
    };

    Ok(())
}
