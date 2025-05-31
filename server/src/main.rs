mod cli;

use std::error::Error;
use std::fs::File;
use std::time::Duration;

use clap::Parser;
use common::payloads::ignore::Ignore;
use common::utils::write_string_vec;
use env_logger::Target;
use log::debug;
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use common::cipher::encryption::chacha20_poly1305::ChaCha20Poly1305;
use common::cipher::encryption::none::NoneCipher;
use common::cipher::encryption::CipherCtx;
use common::cipher::hostkey::rsa_sha2_512::RsaSha2512;
use common::cipher::hostkey::{read_host_key, HostKeyAlgorithm};
use common::cipher::kex::curve25519_sha256::Curve25519Sha256;
use common::cipher::kex::KexAlgorithm;
use common::config;
use common::payloads::kex_ecdh_init::KexEcdhInit;
use common::payloads::kex_ecdh_reply::KexEcdhReply;
use common::payloads::kexinit::KexInit;
use common::payloads::newkeys::NewKeys;
use common::payloads::PayloadFormat;
use common::ssh::SSH;

async fn process(
    stream: TcpStream,
    host_key: Vec<u8>,
    private_key: PrivateKey,
    receiver: broadcast::Receiver<String>,
) {
    let _ = _process(stream, host_key, private_key, receiver).await;
}

async fn _process(
    stream: TcpStream,
    host_key: Vec<u8>,
    private_key: PrivateKey,
    mut receiver: broadcast::Receiver<String>,
) -> Result<(), Box<dyn Error>> {
    let mut ssh = SSH::<NoneCipher>::new(stream, CipherCtx::DUMMY, CipherCtx::DUMMY);
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
    server_host_key_payload.write_all(&host_key).await?;

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

    let signature = match private_key.key_data() {
        ssh_key::private::KeypairData::Rsa(keypair) => {
            RsaSha2512::sign("rsa-sha2-512", &exchange_hash, keypair).await?
        }
        _ => unimplemented!(),
    };
    ssh.write_payload(
        &KexEcdhReply::new(
            "ssh-rsa".to_string(),
            host_key,
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

    loop {
        let command = receiver.recv().await?;
        ssh.write_payload(&Ignore::new(command.as_bytes().to_vec()))
            .await?;
    }
}

async fn interactive(sender: broadcast::Sender<String>) {
    _interactive(sender).await;
}

async fn _interactive(sender: broadcast::Sender<String>) -> Result<(), Box<dyn Error>> {
    let mut stdin = tokio::io::stdin();
    loop {
        let mut buffer = String::new();
        loop {
            let c = stdin.read_u8().await?;
            if c == b'\n' || c == b'\r' {
                break;
            }

            buffer.push(c as char);
        }

        debug!("Sending {:?}", buffer);
        let _ = sender.send(buffer);
    }
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

    let (send, _) = broadcast::channel(100);
    tokio::spawn(interactive(send.clone()));
    loop {
        let (socket, addr) = listener.accept().await?;
        debug!("New client: {}", addr);

        let receiver = send.subscribe();
        tokio::spawn(process(socket, ukey.clone(), rkey.clone(), receiver));
    }
}
