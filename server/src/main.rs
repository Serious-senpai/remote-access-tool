mod cipher;
mod config;
mod errors;
mod packets;
mod payloads;
mod sshkey;
mod utils;

use std::error::Error;

use log::{debug, info};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::sha2::{Sha256, Sha512};
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use cipher::chacha20poly1305::ChaCha20Poly1305;
use cipher::none::NoneCipher;
use cipher::{Cipher, CipherCtx};
use packets::Packet;
use payloads::kex_ecdh_init::KexEcdhInit;
use payloads::kex_ecdh_reply::KexEcdhReply;
use payloads::kexinit::KexInit;
use payloads::newkeys::NewKeys;
use payloads::service_accept::ServiceAccept;
use payloads::service_request::ServiceRequest;
use payloads::userauth_failure::UserauthFailure;
use payloads::userauth_request::{UserauthMethod, UserauthRequest};
use payloads::PayloadFormat;
use sshkey::Ed25519KeyPair;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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

    let key_pair = Ed25519KeyPair::new();

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
        "Host public key is e = {}, n = {}",
        server_kex_ecdh_reply.server_host_key.e(),
        server_kex_ecdh_reply.server_host_key.n(),
    );

    let shared_secret = Ed25519KeyPair::x25519(
        key_pair.private_seed.clone(),
        server_kex_ecdh_reply.public_key.clone(),
    );

    let exchange_hash = server_kex_ecdh_reply
        .exchange_hash(
            config::SSH_ID_STRING.as_bytes(),
            server_id_string.as_bytes(),
            &client_kexinit_packet.payload,
            &server_kexinit_packet.payload,
            &key_pair.public_key,
            &shared_secret,
        )
        .await?;

    let verify_key = VerifyingKey::<Sha512>::new(server_kex_ecdh_reply.server_host_key.clone());
    let signature = Signature::try_from(server_kex_ecdh_reply.signature.as_slice())?;

    verify_key.verify(&exchange_hash, &signature)?;

    let client_newkeys = NewKeys {};
    client_newkeys
        .to_packet::<NoneCipher>(&CipherCtx::DUMMY)
        .await?
        .to_stream(&CipherCtx::DUMMY, &mut stream)
        .await?;

    NewKeys::from_packet(&Packet::<NoneCipher>::from_stream(&CipherCtx::DUMMY, &mut stream).await?)
        .await?;

    let session_id = exchange_hash;

    let mut send_ctx = CipherCtx {
        seq: 3,
        iv: &[],
        enc_key: &ChaCha20Poly1305::expand_key::<Sha256, 64>(
            &shared_secret,
            &exchange_hash,
            &session_id,
            b'C',
        )
        .await?,
        int_key: &[],
    };
    let mut receive_ctx = CipherCtx {
        seq: 3,
        iv: &[],
        enc_key: &ChaCha20Poly1305::expand_key::<Sha256, 64>(
            &shared_secret,
            &exchange_hash,
            &session_id,
            b'D',
        )
        .await?,
        int_key: &[],
    };

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

    let client_userauth_request = UserauthRequest {
        username: String::from("sshd"),
        service_name: String::from("ssh-userauth"),
        method_name: UserauthMethod::None,
    };
    client_userauth_request
        .to_packet::<ChaCha20Poly1305>(&send_ctx)
        .await?
        .to_stream(&send_ctx, &mut stream)
        .await?;
    send_ctx.seq += 1;

    let server_userauth_failure = UserauthFailure::from_packet::<ChaCha20Poly1305>(
        &Packet::<ChaCha20Poly1305>::from_stream(&receive_ctx, &mut stream).await?,
    )
    .await?;
    receive_ctx.seq += 1;

    debug!(
        "SSH_MSG_USERAUTH_FAILURE: methods = {:?}, partial_success = {}",
        server_userauth_failure.methods, server_userauth_failure.partial_success
    );

    let client_userauth_request = UserauthRequest {
        username: String::from("sshd"),
        service_name: String::from("ssh-userauth"),
        method_name: UserauthMethod::Password {
            password: String::from(""),
        },
    };
    client_userauth_request
        .to_packet::<ChaCha20Poly1305>(&send_ctx)
        .await?
        .to_stream(&send_ctx, &mut stream)
        .await?;
    send_ctx.seq += 1;

    Ok(())
}
