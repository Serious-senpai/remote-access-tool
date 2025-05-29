use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct NewKeys {}

#[async_trait]
impl PayloadFormat for NewKeys {
    const OPCODE: u8 = 21;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        Ok(Self {})
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        Ok(())
    }
}
