use std::error::Error;
use std::net::SocketAddr;

use common::cipher::encryption::none::NoneCipher;
use common::cipher::encryption::{Cipher, CipherCtx};
use common::cipher::hostkey::HostKeyAlgorithm;
use common::cipher::kex::KexAlgorithm;
use common::errors::RuntimeError;
use common::packets::Packet;
use common::payloads::kex_ecdh_init::KexEcdhInit;
use common::payloads::kex_ecdh_reply::KexEcdhReply;
use common::payloads::kexinit::KexInit;
use common::payloads::newkeys::NewKeys;
use common::payloads::PayloadFormat;
use common::ssh::SSH;
use common::{config, log_error};
use log::{debug, error};
use ssh_key::PrivateKey;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

/// Client communication layer
///
/// Cardinality: many (1 per client)
pub struct ClientLayer<C>
where
    C: Cipher,
{
    _addr: SocketAddr,
    _ssh: SSH<C>,
}

impl<C> ClientLayer<C>
where
    C: Cipher + Sync,
{
    pub async fn accept_connection<K, H>(
        socket: TcpStream,
        addr: SocketAddr,
        host_key: Vec<u8>,
        private_key: PrivateKey,
    ) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        K: KexAlgorithm,
        H: HostKeyAlgorithm,
    {
        let mut ssh = SSH::<NoneCipher>::new(socket, CipherCtx::DUMMY, CipherCtx::DUMMY);
        log_error!(ssh.write_version_string(&config::SSH_ID_STRING).await);

        let client_id_string = log_error!(ssh.read_version_string(true).await);

        let server_kexinit_packet = log_error!(
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
        let client_kexinit_packet = log_error!(ssh.read_packet().await);
        let client_kexinit = log_error!(KexInit::from_packet(&client_kexinit_packet).await);

        if !client_kexinit.has_kex::<K>() {
            error!(
                "Client does not support the required KEX algorithm: {}",
                K::NAME
            );
            return Err(RuntimeError::new("Unsupported KEX algorithm"))?;
        }

        if !client_kexinit.has_host_key::<H>() {
            error!(
                "Client does not support the required host key algorithm: {}",
                H::SIGNATURE_ALGORITHM
            );
            return Err(RuntimeError::new("Unsupported host key algorithm"))?;
        }

        if !client_kexinit.has_encryption::<C>() {
            error!(
                "Client does not support the required encryption algorithm: {}",
                C::NAME
            );
            return Err(RuntimeError::new("Unsupported encryption algorithm"))?;
        }

        let temp = log_error!(ssh.read_packet().await);
        let temp = log_error!(KexEcdhInit::from_packet(&temp).await);
        let client_ukey = temp.public_key();

        let key_pair = K::new("");
        let shared_secret =
            K::shared_secret(key_pair.private_seed().to_vec(), client_ukey.to_vec())?;

        let server_host_key_payload =
            KexEcdhReply::create_server_host_key_payload(&host_key, H::HOST_KEY_ALGORITHM).await;

        let exchange_hash = K::exchange_hash(
            client_id_string.as_bytes(),
            config::SSH_ID_STRING.as_bytes(),
            &client_kexinit_packet.payload,
            &server_kexinit_packet.payload,
            &server_host_key_payload,
            client_ukey,
            key_pair.public_key(),
            &shared_secret,
        )
        .await;
        let server_kex_ecdh_reply = log_error!(
            KexEcdhReply::new::<H>(
                host_key,
                key_pair.public_key().to_vec(),
                &private_key,
                &exchange_hash,
            )
            .await
        );

        log_error!(ssh.write_payload(&server_kex_ecdh_reply).await);

        log_error!(ssh.write_payload(&NewKeys {}).await);
        let temp = log_error!(ssh.read_packet().await);
        log_error!(NewKeys::from_packet(&temp).await);

        let session_id = &exchange_hash;
        let ssh = log_error!(
            ssh.switch_encryption::<K, C, true>(&shared_secret, &exchange_hash, session_id)
                .await
        );

        Ok(Self {
            _addr: addr,
            _ssh: ssh,
        })
    }

    /// The infinite loop that continuously does the following tasks:
    /// - Reads [Packet]s from SSH peer and sends them to higher levels.
    /// - Receives [Packet]s from higher levels and sends them to the SSH peer.
    pub async fn listen_loop(
        mut self,
        sender: broadcast::Sender<(SocketAddr, Packet<C>)>,
        mut receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        loop {
            tokio::select! {
                Some(payload) = receiver.recv() => {
                    debug!("Sending {} bytes of payload to {}", payload.len(), self._addr);
                    if let Err(e) = self._ssh.write_raw_payload(payload).await {
                        error!("Unable to send packet to {}: {}", self._addr, e);
                        return Err(e)?;
                    }
                }
                packet = self._ssh.read_packet() => {
                    let packet = log_error!(packet);
                    if let Err(e) = sender.send((self._addr, packet)) {
                        error!(
                            "Received a packet from {}, but unable to notify higher levels: {}",
                            self._addr, e
                        );
                    }
                }
            }
        }
    }
}
