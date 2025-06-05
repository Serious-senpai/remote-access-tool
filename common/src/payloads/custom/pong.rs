use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::super::utils::{read_string, write_string};
use super::super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct Pong {
    _data: u8,
    _version: String,
}

#[async_trait]
impl PayloadFormat for Pong {
    const OPCODE: u8 = 194;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let data = stream.read_u8().await?;
        let version = read_string(stream).await?;
        let version = String::from_utf8(version)?;

        Ok(Self {
            _data: data,
            _version: version,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_u8(self._data).await?;
        write_string(stream, self._version.as_bytes()).await?;
        Ok(())
    }
}

impl Pong {
    pub fn new(data: u8, version: impl Into<String>) -> Self {
        Self {
            _data: data,
            _version: version.into(),
        }
    }

    pub fn data(&self) -> u8 {
        self._data
    }

    pub fn version(&self) -> &str {
        &self._version
    }
}
