use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::utils::{read_string, write_string};
use super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct Ignore {
    data: Vec<u8>,
}

#[async_trait]
impl PayloadFormat for Ignore {
    const OPCODE: u8 = 2;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let data = read_string(stream).await?;

        Ok(Self { data })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        write_string(stream, &self.data).await?;
        Ok(())
    }
}

impl Ignore {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}
