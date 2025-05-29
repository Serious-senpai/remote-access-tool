use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::errors::RuntimeError;
use super::super::utils::{read_string, write_string};
use super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct KexEcdhInit {
    pub public_key: [u8; 32],
}

#[async_trait]
impl PayloadFormat for KexEcdhInit {
    const OPCODE: u8 = 30;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let public_key = read_string(stream).await?;

        Ok(Self {
            public_key: public_key
                .try_into()
                .map_err(|_| RuntimeError::new("Invalid public key length"))?,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        write_string(stream, &self.public_key).await?;

        Ok(())
    }
}
