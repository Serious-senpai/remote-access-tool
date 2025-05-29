use std::error::Error;
use std::io::{self, Write};

use clap::Parser;
use common::cipher::hostkey::HostKeyAlgorithm;
use log::{debug, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use common::cipher::encryption::chacha20_poly1305::ChaCha20Poly1305;
use common::cipher::encryption::none::NoneCipher;
use common::cipher::encryption::CipherCtx;
use common::cipher::hostkey::rsa_sha2_512::RsaSha2512;
use common::cipher::kex::curve25519_sha256::Curve25519Sha256;
use common::cipher::kex::KexAlgorithm;
use common::config;
use common::packets::Packet;
use common::payloads::disconnect::Disconnect;
use common::payloads::kex_ecdh_init::KexEcdhInit;
use common::payloads::kex_ecdh_reply::KexEcdhReply;
use common::payloads::kexinit::KexInit;
use common::payloads::newkeys::NewKeys;
use common::payloads::service_accept::ServiceAccept;
use common::payloads::service_request::ServiceRequest;
use common::payloads::userauth_failure::UserauthFailure;
use common::payloads::userauth_request::{UserauthMethod, UserauthRequest};
use common::payloads::PayloadFormat;

#[derive(Debug, Parser)]
#[command(
    long_about = "Remote Access Tool (RAT) server component",
    propagate_version = true,
    version
)]
pub struct Arguments {
    /// The username to use for authentication
    username: String,

    /// Path to the private key file for authentication (`ssh-userauth` method name = "publickey").
    #[arg(short, long)]
    pub key: Option<String>,

    /// Enable interactive authentication (`ssh-userauth` method name = "password").
    #[arg(short, long)]
    pub interactive: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = Arguments::parse();

    let mut log = colog::default_builder();
    log.filter_level(log::LevelFilter::Debug);
    log.init();

    let mut stream = TcpStream::connect("localhost:22").await?;

    stream.readable().await?;
    let server_id_string = {
        let mut buf = vec![];
        loop {
            let byte = stream.read_u8().await?;
            buf.push(byte);
            if byte == b'\n' {
                let line = String::from_utf8(buf)?;

                // Remove the CRLF (i.e. \r\n) characters
                let trimmed = line.trim_end_matches("\r\n");
                info!("{}", trimmed);

                if line.starts_with("SSH-") {
                    break Ok::<String, Box<dyn Error>>(String::from(trimmed));
                }

                buf = vec![];
            }
        }?
    };

    stream.writable().await?;
    stream.write(config::SSH_ID_STRING.as_bytes()).await?;
    stream.write(b"\r\n").await?;

    let client_kexinit = KexInit::new();
    let client_kexinit_packet = client_kexinit
        .to_packet::<NoneCipher>(&CipherCtx::DUMMY)
        .await?;
    client_kexinit_packet
        .to_stream(&CipherCtx::DUMMY, &mut stream)
        .await?;

    let server_kexinit_packet =
        Packet::<NoneCipher>::from_stream(&CipherCtx::DUMMY, &mut stream).await?;

    let key_pair = Curve25519Sha256::new();

    let kex_ecdh_init = KexEcdhInit {
        public_key: key_pair.public_key.clone(),
    };
    kex_ecdh_init
        .to_packet::<NoneCipher>(&CipherCtx::DUMMY)
        .await?
        .to_stream(&CipherCtx::DUMMY, &mut stream)
        .await?;

    let server_kex_ecdh_reply = KexEcdhReply::from_packet(
        &Packet::<NoneCipher>::from_stream(&CipherCtx::DUMMY, &mut stream).await?,
    )
    .await?;

    info!(
        "Host public key is {:?}",
        server_kex_ecdh_reply.server_host_key,
    );

    let shared_secret = Curve25519Sha256::shared_secret(
        key_pair.private_seed.to_vec(),
        server_kex_ecdh_reply.public_key.clone(),
    )?;

    let exchange_hash = Curve25519Sha256::exchange_hash(
        config::SSH_ID_STRING.as_bytes(),
        server_id_string.as_bytes(),
        &client_kexinit_packet.payload,
        &server_kexinit_packet.payload,
        &server_kex_ecdh_reply.server_host_key_payload,
        &key_pair.public_key,
        &server_kex_ecdh_reply.public_key,
        &shared_secret,
    )
    .await;

    RsaSha2512::verify(
        &server_kex_ecdh_reply.signature_algorithm,
        &exchange_hash,
        &server_kex_ecdh_reply.signature,
        &server_kex_ecdh_reply.server_host_key,
    )
    .await?;

    let client_newkeys = NewKeys {};
    client_newkeys
        .to_packet::<NoneCipher>(&CipherCtx::DUMMY)
        .await?
        .to_stream(&CipherCtx::DUMMY, &mut stream)
        .await?;

    NewKeys::from_packet(&Packet::<NoneCipher>::from_stream(&CipherCtx::DUMMY, &mut stream).await?)
        .await?;

    let session_id = &exchange_hash;

    let mut send_ctx = CipherCtx::new::<Curve25519Sha256>(
        3,
        b'A',
        b'C',
        b'E',
        &shared_secret,
        &exchange_hash,
        session_id,
    )
    .await?;
    let mut receive_ctx = CipherCtx::new::<Curve25519Sha256>(
        3,
        b'B',
        b'D',
        b'F',
        &shared_secret,
        &exchange_hash,
        session_id,
    )
    .await?;

    let client_service_request = ServiceRequest {
        service_name: String::from("ssh-userauth"),
    };
    client_service_request
        .to_packet::<ChaCha20Poly1305>(&send_ctx)
        .await?
        .to_stream(&send_ctx, &mut stream)
        .await?;
    send_ctx.seq += 1;

    let server_service_accept = ServiceAccept::from_packet::<ChaCha20Poly1305>(
        &Packet::<ChaCha20Poly1305>::from_stream(&receive_ctx, &mut stream).await?,
    )
    .await?;
    receive_ctx.seq += 1;
    debug!(
        "SSH_MSG_SERVICE_ACCEPT: {:?}",
        server_service_accept.service_name
    );

    let mut username = arguments.username;
    let client_userauth_request = UserauthRequest {
        username,
        service_name: String::from("ssh-userauth"),
        method_name: UserauthMethod::None,
    };
    client_userauth_request
        .to_packet::<ChaCha20Poly1305>(&send_ctx)
        .await?
        .to_stream(&send_ctx, &mut stream)
        .await?;
    send_ctx.seq += 1;
    username = client_userauth_request.username;

    let server_userauth_failure = UserauthFailure::from_packet::<ChaCha20Poly1305>(
        &Packet::<ChaCha20Poly1305>::from_stream(&receive_ctx, &mut stream).await?,
    )
    .await?;
    receive_ctx.seq += 1;

    debug!(
        "SSH_MSG_USERAUTH_FAILURE: methods = {:?}, partial_success = {}",
        server_userauth_failure.methods, server_userauth_failure.partial_success
    );

    if arguments.interactive {
        print!("Enter password>");
        io::stdout().flush()?;
        let mut password = String::new();
        io::stdin().read_line(&mut password)?;
        password = password.trim().to_string();

        let client_userauth_request = UserauthRequest {
            username,
            service_name: String::from("ssh-userauth"),
            method_name: UserauthMethod::Password { password },
        };
        client_userauth_request
            .to_packet::<ChaCha20Poly1305>(&send_ctx)
            .await?
            .to_stream(&send_ctx, &mut stream)
            .await?;
        send_ctx.seq += 1;

        let packet = Packet::<ChaCha20Poly1305>::from_stream(&receive_ctx, &mut stream).await?;
        receive_ctx.seq += 1;

        debug!("Response packet = {:?}", packet);
    }

    let client_disconnect = Disconnect {
        reason_code: 11,
        description: String::from("Disconnect normally"),
        language_tag: String::from(""),
    };
    client_disconnect
        .to_packet::<ChaCha20Poly1305>(&send_ctx)
        .await?
        .to_stream(&send_ctx, &mut stream)
        .await?;
    send_ctx.seq += 1;

    Ok(())
}
