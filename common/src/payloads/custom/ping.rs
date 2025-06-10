use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::payloads::PayloadFormat;

#[derive(Debug, Clone)]
pub struct Ping {
    _data: u8,
}

#[async_trait]
impl PayloadFormat for Ping {
    const OPCODE: u8 = 196;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let data = stream.read_u8().await?;

        Ok(Self { _data: data })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_u8(self._data).await?;
        Ok(())
    }
}

impl Ping {
    pub fn new(data: u8) -> Self {
        Self { _data: data }
    }

    pub fn data(&self) -> u8 {
        self._data
    }
}
