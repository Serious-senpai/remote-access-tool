use std::error::Error;
use std::fmt::Write;

use async_trait::async_trait;
use rsa::sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

use super::super::utils::{read_string, write_string, write_string_vec};
use super::PayloadFormat;

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

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
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

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
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
    pub async fn new(
        server_host_key_algorithm: String,
        server_host_key: Vec<u8>,
        public_key: Vec<u8>,
        signature_algorithm: String,
        signature: Vec<u8>,
    ) -> Self {
        let mut server_host_key_payload = vec![];
        write_string_vec(
            &mut server_host_key_payload,
            server_host_key_algorithm.as_bytes(),
        )
        .await;
        server_host_key_payload.extend_from_slice(&server_host_key);

        Self {
            server_host_key_payload,
            server_host_key_algorithm,
            server_host_key,
            public_key,
            signature_algorithm,
            signature,
        }
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
