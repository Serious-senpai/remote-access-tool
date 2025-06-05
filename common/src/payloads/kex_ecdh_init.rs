use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::utils::{read_string, write_string};
use super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct KexEcdhInit {
    public_key: Vec<u8>,
}

#[async_trait]
impl PayloadFormat for KexEcdhInit {
    const OPCODE: u8 = 30;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let public_key = read_string(stream).await?;

        Ok(Self { public_key })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        write_string(stream, &self.public_key).await?;

        Ok(())
    }
}

impl KexEcdhInit {
    pub fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}
