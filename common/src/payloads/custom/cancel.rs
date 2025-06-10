use std::error::Error;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::payloads::PayloadFormat;
use crate::utils::{read_address, write_address};

#[derive(Debug, Clone)]
pub struct Cancel {
    _request_id: u32,
    _src: SocketAddr,
}

#[async_trait]
impl PayloadFormat for Cancel {
    const OPCODE: u8 = 194;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let request_id = stream.read_u32().await?;
        let src = read_address(stream).await?;

        Ok(Self {
            _request_id: request_id,
            _src: src,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_u32(self._request_id).await?;
        write_address(stream, &self._src).await?;

        Ok(())
    }
}

impl Cancel {
    pub fn new(request_id: u32, src: SocketAddr) -> Self {
        Self {
            _request_id: request_id,
            _src: src,
        }
    }

    pub fn request_id(&self) -> u32 {
        self._request_id
    }

    pub fn src(&self) -> SocketAddr {
        self._src
    }
}
