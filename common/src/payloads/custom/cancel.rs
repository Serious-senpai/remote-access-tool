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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_cancel_round_trip() {
        let request_id = 12345;
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);
        let cancel = Cancel::new(request_id, src);

        // Write to Vec
        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            cancel.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Read from Vec
        let mut reader = BufReader::new(&buffer[..]);
        let parsed_cancel = Cancel::from_stream(&mut reader).await.unwrap();

        assert_eq!(parsed_cancel.request_id(), request_id);
        assert_eq!(parsed_cancel.src(), src);
    }

    #[tokio::test]
    async fn test_cancel_opcode() {
        let cancel = Cancel::new(0, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            cancel.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        assert_eq!(buffer[0], Cancel::OPCODE);
    }

    #[tokio::test]
    async fn test_cancel_getters() {
        let request_id = 98765;
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        let cancel = Cancel::new(request_id, src);

        assert_eq!(cancel.request_id(), request_id);
        assert_eq!(cancel.src(), src);
    }
}
