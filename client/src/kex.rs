use std::error::Error;

use common::cipher::encryption::none::NoneCipher;
use common::cipher::encryption::{Cipher, CipherCtx};
use common::cipher::hostkey::HostKeyAlgorithm;
use common::cipher::kex::KexAlgorithm;
use common::errors::RuntimeError;
use common::payloads::kex_ecdh_init::KexEcdhInit;
use common::payloads::kex_ecdh_reply::KexEcdhReply;
use common::payloads::kexinit::KexInit;
use common::payloads::newkeys::NewKeys;
use common::payloads::PayloadFormat;
use common::ssh::SSH;
use common::{config, log_error};
use log::{debug, error, info};
use tokio::net::TcpStream;

pub async fn key_exchange<C, K, H>(
    stream: TcpStream,
) -> Result<SSH<C>, Box<dyn Error + Send + Sync>>
where
    C: Cipher,
    K: KexAlgorithm,
    H: HostKeyAlgorithm,
{
    let ssh = SSH::<NoneCipher>::new(stream, CipherCtx::DUMMY, CipherCtx::DUMMY);

    log_error!(ssh.write_version_string(&config::SSH_ID_STRING).await);
    let server_id_string = log_error!(ssh.read_version_string(true).await);

    let client_kexinit_packet = log_error!(
        ssh.write_payload(&KexInit::new(
            vec![K::NAME.to_string()],
            vec![H::SIGNATURE_ALGORITHM],
            vec![C::NAME],
            vec![C::NAME],
            vec!["none"],
            vec!["none"],
            vec!["none"],
            vec!["none"],
            vec![""],
            vec![""],
            false
        ))
        .await
    );
    let server_kexinit_packet = log_error!(ssh.read_packet().await);
    let server_kexinit = log_error!(KexInit::from_packet(&server_kexinit_packet).await);

    if !server_kexinit.has_kex::<K>() {
        error!(
            "Server does not support the required KEX algorithm: {}. Their offer: {:?}",
            K::NAME,
            server_kexinit.kex_algorithms()
        );
        return Err(RuntimeError::new("Unsupported KEX algorithm"))?;
    }

    if !server_kexinit.has_host_key::<H>() {
        error!(
            "Server does not support the required host key algorithm: {}. Their offer: {:?}",
            H::SIGNATURE_ALGORITHM,
            server_kexinit.server_host_key_algorithms()
        );
        return Err(RuntimeError::new("Unsupported host key algorithm"))?;
    }

    if !server_kexinit.has_encryption::<C>() {
        error!(
            "Server does not support the required encryption algorithm: {}. Their offer: {:?} and {:?}",
            C::NAME,
            server_kexinit.encryption_algorithms_client_to_server(),
            server_kexinit.encryption_algorithms_server_to_client()
        );
        return Err(RuntimeError::new("Unsupported encryption algorithm"))?;
    }

    let key_pair = K::new("");

    log_error!(
        ssh.write_payload(&KexEcdhInit::new(key_pair.public_key().to_vec()))
            .await
    );
    let server_kex_ecdh_reply =
        log_error!(KexEcdhReply::from_packet(&log_error!(ssh.read_packet().await)).await);

    info!(
        "Host public key is {}",
        server_kex_ecdh_reply.server_host_key_digest(),
    );

    let shared_secret = K::shared_secret(
        key_pair.private_seed().to_vec(),
        server_kex_ecdh_reply.public_key().to_vec(),
    )?;

    let exchange_hash = K::exchange_hash(
        config::SSH_ID_STRING.as_bytes(),
        server_id_string.as_bytes(),
        &client_kexinit_packet.payload,
        &server_kexinit_packet.payload,
        server_kex_ecdh_reply.server_host_key_payload(),
        key_pair.public_key(),
        server_kex_ecdh_reply.public_key(),
        &shared_secret,
    )
    .await;

    log_error!(
        H::verify(
            &exchange_hash,
            server_kex_ecdh_reply.signature(),
            server_kex_ecdh_reply.server_host_key(),
        )
        .await
    );
    debug!("Signature verified successfully");

    ssh.write_payload(&NewKeys {}).await?;
    NewKeys::from_packet(&ssh.read_packet().await?).await?;

    let session_id = &exchange_hash;
    let ssh = ssh
        .switch_encryption::<K, C, false>(&shared_secret, &exchange_hash, session_id)
        .await?;

    Ok(ssh)
}
