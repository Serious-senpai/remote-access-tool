use std::error::Error;

use rsa::sha2::{Digest, Sha256};
use rsa::{BigUint, RsaPublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

use crate::errors::RuntimeError;
use crate::payloads::format::PayloadFormat;
use crate::utils::{read_biguint, read_string, write_biguint, write_string};

#[derive(Debug, Clone)]
pub struct KexEcdhReply {
    k_s: Vec<u8>,
    pub server_host_key: RsaPublicKey,
    pub public_key: [u8; 32],
    pub signature: Vec<u8>,
}

impl PayloadFormat for KexEcdhReply {
    const OPCODE: u8 = 31;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized,
        S: tokio::io::AsyncReadExt + Unpin,
    {
        let opcode = stream.read_u8().await?;
        Self::check_opcode(opcode)?;

        // Read K_S
        let k_s = read_string(stream).await?;
        let mut reader = BufReader::new(k_s.as_slice());
        for &c in Self::K_S_PREFIX {
            if reader.read_u8().await? != c {
                return Err(RuntimeError::new(format!(
                    "Expected \"{:?}\" for KEX_ECDH_REPLY",
                    Self::K_S_PREFIX
                )))?;
            }
        }
        let e = read_biguint(&mut reader).await?;
        let n = read_biguint(&mut reader).await?;
        let server_host_key = RsaPublicKey::new(n, e)?;

        // Read Q_S
        let public_key = read_string(stream).await?;

        // Read SIG_S
        let sig_s = read_string(stream).await?;
        let mut reader = BufReader::new(sig_s.as_slice());
        for &c in Self::SIG_S_PREFIX {
            if reader.read_u8().await? != c {
                return Err(RuntimeError::new(format!(
                    "Expected \"{:?}\" for KEX_ECDH_REPLY",
                    Self::SIG_S_PREFIX
                )))?;
            }
        }
        let signature = read_string(&mut reader).await?;

        Ok(Self {
            k_s,
            server_host_key,
            public_key: public_key
                .try_into()
                .map_err(|_| RuntimeError::new("Invalid public key length"))?,
            signature,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn std::error::Error>>
    where
        Self: Sized,
        S: AsyncWriteExt + Unpin,
    {
        stream.write_u8(Self::OPCODE).await?;

        todo!();
    }
}

impl KexEcdhReply {
    const K_S_PREFIX: &[u8] = b"\x00\x00\x00\x07ssh-rsa";
    const SIG_S_PREFIX: &[u8] = b"\x00\x00\x00\x0crsa-sha2-512";

    pub async fn exchange_hash(
        &self,
        client_id: &[u8],
        server_id: &[u8],
        client_kexinit: &[u8],
        server_kexinit: &[u8],
        client_public_key: &[u8],
        shared_secret: &[u8],
    ) -> Result<[u8; 32], Box<dyn Error>> {
        let mut buffer = vec![];

        // ID strings of client and server, without CRLF
        write_string(&mut buffer, client_id).await?;
        write_string(&mut buffer, server_id).await?;

        // KEXINIT payloads sent by client and server
        write_string(&mut buffer, client_kexinit).await?;
        write_string(&mut buffer, server_kexinit).await?;

        // Server public host key
        write_string(&mut buffer, &self.k_s).await?;

        // Public keys of client and server
        write_string(&mut buffer, client_public_key).await?;
        write_string(&mut buffer, &self.public_key).await?;

        // Shared secret
        let shared_secret_value = BigUint::from_bytes_be(shared_secret);
        write_biguint(&mut buffer, &shared_secret_value).await?;

        // eprintln!("buffer = {:?}", buffer);
        Ok(Sha256::digest(&buffer).into())
    }
}
