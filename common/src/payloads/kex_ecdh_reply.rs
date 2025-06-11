use std::error::Error;
use std::fmt::Write;

use async_trait::async_trait;
use rsa::sha2::{Digest, Sha256};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

use crate::cipher::hostkey::HostKeyAlgorithm;
use crate::payloads::PayloadFormat;
use crate::utils::{read_string, write_string, write_string_vec};

#[derive(Debug, Clone)]
pub struct KexEcdhReply {
    server_host_key_payload: Vec<u8>,
    server_host_key_algorithm: String,
    server_host_key: Vec<u8>,
    public_key: Vec<u8>,
    signature_algorithm: String,
    signature: Vec<u8>,
}

#[async_trait]
impl PayloadFormat for KexEcdhReply {
    const OPCODE: u8 = 31;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        // Read K_S
        let k_s = read_string(stream).await?;
        let mut reader = BufReader::new(k_s.as_slice());

        let server_host_key_algorithm = read_string(&mut reader).await?;
        let server_host_key_algorithm = String::from_utf8(server_host_key_algorithm)?;

        let mut server_host_key = vec![];
        reader.read_to_end(&mut server_host_key).await?;

        // Read Q_S
        let public_key = read_string(stream).await?;

        // Read SIG_S
        let sig_s = read_string(stream).await?;
        let mut reader = BufReader::new(sig_s.as_slice());

        let signature_algorithm = read_string(&mut reader).await?;
        let signature_algorithm = String::from_utf8(signature_algorithm)?;

        let signature = read_string(&mut reader).await?;

        Ok(Self {
            server_host_key_payload: k_s,
            server_host_key_algorithm,
            server_host_key,
            public_key,
            signature_algorithm,
            signature,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        write_string(stream, &self.server_host_key_payload).await?;
        write_string(stream, &self.public_key).await?;

        let mut sig_s = vec![];
        write_string_vec(&mut sig_s, self.signature_algorithm.as_bytes()).await;
        write_string_vec(&mut sig_s, &self.signature).await;

        write_string(stream, &sig_s).await?;
        Ok(())
    }
}

impl KexEcdhReply {
    pub async fn new<H>(
        server_host_key: Vec<u8>,
        public_key: Vec<u8>,
        private_key: &PrivateKey,
        exchange_hash: &[u8],
    ) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        H: HostKeyAlgorithm,
    {
        let server_host_key_algorithm = H::HOST_KEY_ALGORITHM.to_string();
        let server_host_key_payload =
            Self::create_server_host_key_payload(&server_host_key, &server_host_key_algorithm)
                .await;

        let signature = H::sign(exchange_hash, private_key).await?;

        Ok(Self {
            server_host_key_payload,
            server_host_key_algorithm,
            server_host_key,
            public_key,
            signature_algorithm: H::SIGNATURE_ALGORITHM.to_string(),
            signature,
        })
    }

    pub async fn create_server_host_key_payload(
        server_host_key: &[u8],
        server_host_key_algorithm: &str,
    ) -> Vec<u8> {
        let mut server_host_key_payload = vec![];
        write_string_vec(
            &mut server_host_key_payload,
            server_host_key_algorithm.as_bytes(),
        )
        .await;
        server_host_key_payload.extend_from_slice(server_host_key);
        server_host_key_payload
    }

    pub fn server_host_key_digest(&self) -> String {
        Sha256::digest(&self.server_host_key_payload)
            .iter()
            .fold(String::new(), |mut output, b| {
                let _ = write!(output, "{b:02X}");
                output
            })
    }

    pub fn server_host_key_payload(&self) -> &[u8] {
        &self.server_host_key_payload
    }

    pub fn server_host_key_algorithm(&self) -> &str {
        &self.server_host_key_algorithm
    }

    pub fn server_host_key(&self) -> &[u8] {
        &self.server_host_key
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn signature_algorithm(&self) -> &str {
        &self.signature_algorithm
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_from_stream_and_to_stream_roundtrip() {
        // Create test data
        let server_host_key_algorithm = "ssh-rsa";
        let server_host_key = vec![1, 2, 3, 4, 5];
        let server_host_key_payload = KexEcdhReply::create_server_host_key_payload(
            &server_host_key,
            server_host_key_algorithm,
        )
        .await;
        let public_key = vec![10, 20, 30, 40, 50];
        let signature_algorithm = "rsa-sha2-256";
        let signature = vec![100, 200];

        let original = KexEcdhReply {
            server_host_key_payload: server_host_key_payload.clone(),
            server_host_key_algorithm: server_host_key_algorithm.to_string(),
            server_host_key: server_host_key.clone(),
            public_key: public_key.clone(),
            signature_algorithm: signature_algorithm.to_string(),
            signature: signature.clone(),
        };

        // Write to Vec
        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            original.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Read from Vec
        let mut reader = BufReader::new(buffer.as_slice());
        let parsed = KexEcdhReply::from_stream(&mut reader).await.unwrap();

        // Verify roundtrip
        assert_eq!(
            original.server_host_key_algorithm,
            parsed.server_host_key_algorithm
        );
        assert_eq!(original.server_host_key, parsed.server_host_key);
        assert_eq!(original.public_key, parsed.public_key);
        assert_eq!(original.signature_algorithm, parsed.signature_algorithm);
        assert_eq!(original.signature, parsed.signature);
        assert_eq!(
            original.server_host_key_payload,
            parsed.server_host_key_payload
        );
    }

    #[tokio::test]
    async fn test_server_host_key_digest() {
        let kex_reply = KexEcdhReply {
            server_host_key_payload: vec![1, 2, 3, 4],
            server_host_key_algorithm: "ssh-rsa".to_string(),
            server_host_key: vec![5, 6, 7, 8],
            public_key: vec![9, 10, 11, 12],
            signature_algorithm: "rsa-sha2-256".to_string(),
            signature: vec![13, 14, 15, 16],
        };

        let digest = kex_reply.server_host_key_digest();
        assert!(!digest.is_empty());
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_create_server_host_key_payload() {
        let server_host_key = vec![1, 2, 3, 4, 5];
        let algorithm = "ssh-rsa";

        let payload =
            KexEcdhReply::create_server_host_key_payload(&server_host_key, algorithm).await;

        // Verify the payload contains the algorithm and key data
        assert!(payload.len() > server_host_key.len());
        assert!(payload.ends_with(&server_host_key));
    }

    #[tokio::test]
    async fn test_getters() {
        let server_host_key_payload = vec![1, 2, 3, 4];
        let server_host_key_algorithm = "ssh-rsa".to_string();
        let server_host_key = vec![5, 6, 7, 8];
        let public_key = vec![9, 10, 11, 12];
        let signature_algorithm = "rsa-sha2-256".to_string();
        let signature = vec![13, 14, 15, 16];

        let kex_reply = KexEcdhReply {
            server_host_key_payload: server_host_key_payload.clone(),
            server_host_key_algorithm: server_host_key_algorithm.clone(),
            server_host_key: server_host_key.clone(),
            public_key: public_key.clone(),
            signature_algorithm: signature_algorithm.clone(),
            signature: signature.clone(),
        };

        assert_eq!(
            kex_reply.server_host_key_payload(),
            &server_host_key_payload
        );
        assert_eq!(
            kex_reply.server_host_key_algorithm(),
            &server_host_key_algorithm
        );
        assert_eq!(kex_reply.server_host_key(), &server_host_key);
        assert_eq!(kex_reply.public_key(), &public_key);
        assert_eq!(kex_reply.signature_algorithm(), &signature_algorithm);
        assert_eq!(kex_reply.signature(), &signature);
    }
}
