mod cli;

use std::error::Error;

use clap::Parser;
use log::{debug, info};
use tokio::net::TcpStream;

use common::cipher::encryption::chacha20_poly1305::ChaCha20Poly1305;
use common::cipher::encryption::none::NoneCipher;
use common::cipher::encryption::CipherCtx;
use common::cipher::hostkey::rsa_sha2_512::RsaSha2512;
use common::cipher::hostkey::HostKeyAlgorithm;
use common::cipher::kex::curve25519_sha256::Curve25519Sha256;
use common::cipher::kex::KexAlgorithm;
use common::config;
use common::payloads::kex_ecdh_init::KexEcdhInit;
use common::payloads::kex_ecdh_reply::KexEcdhReply;
use common::payloads::kexinit::KexInit;
use common::payloads::newkeys::NewKeys;
use common::payloads::PayloadFormat;
use common::ssh::SSH;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = cli::Arguments::parse();

    let mut log = colog::default_builder();
    log.filter_level(log::LevelFilter::Debug);
    log.init();

    let stream = TcpStream::connect("localhost:22").await?;

    let mut ssh = SSH::<NoneCipher>::new(stream, CipherCtx::DUMMY, CipherCtx::DUMMY);
    ssh.write_version_string(config::SSH_ID_STRING).await?;
    let server_id_string = ssh.read_version_string(true).await?;

    let client_kexinit_packet = ssh.write_payload(&KexInit::new()).await?;
    let server_kexinit_packet = &ssh.read_packet().await?;
    // TODO: Check supported algorithms

    let key_pair = Curve25519Sha256::new("");

    ssh.write_payload(&KexEcdhInit::new(key_pair.public_key.to_vec()))
        .await?;

    let server_kex_ecdh_reply = KexEcdhReply::from_packet(&ssh.read_packet().await?).await?;

    info!(
        "Host public key is {}",
        server_kex_ecdh_reply.server_host_key_digest(),
    );

    let shared_secret = Curve25519Sha256::shared_secret(
        key_pair.private_seed.to_vec(),
        server_kex_ecdh_reply.public_key().to_vec(),
    )?;

    let exchange_hash = Curve25519Sha256::exchange_hash(
        config::SSH_ID_STRING.as_bytes(),
        server_id_string.as_bytes(),
        &client_kexinit_packet.payload,
        &server_kexinit_packet.payload,
        server_kex_ecdh_reply.server_host_key_payload(),
        &key_pair.public_key,
        server_kex_ecdh_reply.public_key(),
        &shared_secret,
    )
    .await;

    RsaSha2512::verify(
        server_kex_ecdh_reply.signature_algorithm(),
        &exchange_hash,
        server_kex_ecdh_reply.signature(),
        server_kex_ecdh_reply.server_host_key(),
    )
    .await?;
    debug!("Signature verified successfully");

    ssh.write_payload(&NewKeys {}).await?;
    NewKeys::from_packet(&ssh.read_packet().await?).await?;

    let session_id = &exchange_hash;
    let mut ssh = ssh
        .switch_encryption::<Curve25519Sha256, ChaCha20Poly1305, false>(
            &shared_secret,
            &exchange_hash,
            session_id,
        )
        .await?;

    loop {
        let packet = ssh.read_packet().await?;
        debug!("Received packet: {:?}", packet);
    }
}
