use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

use super::super::utils::read_string;
use super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct KexEcdhReply {
    pub server_host_key_payload: Vec<u8>,
    pub server_host_key_algorithm: String,
    pub server_host_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature_algorithm: String,
    pub signature: Vec<u8>,
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

        todo!();
    }
}
