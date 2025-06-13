use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::payloads::custom::ping::Ping;
use crate::payloads::PayloadFormat;

#[derive(Debug, Clone)]
pub struct Pong {
    _data: u8,
}

#[async_trait]
impl PayloadFormat for Pong {
    const OPCODE: u8 = 197;

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

impl Pong {
    pub fn new(data: u8) -> Self {
        Self { _data: data }
    }

    pub fn from_ping(ping: &Ping) -> Self {
        Self {
            _data: ping.data().wrapping_add(1),
        }
    }

    pub fn data(&self) -> u8 {
        self._data
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_pong_new() {
        let pong = Pong::new(42);
        assert_eq!(pong.data(), 42);
    }

    #[tokio::test]
    async fn test_pong_from_ping() {
        let ping = Ping::new(100);
        let pong = Pong::from_ping(&ping);
        assert_eq!(pong.data(), 101);
    }

    #[tokio::test]
    async fn test_pong_from_ping_wrapping() {
        let ping = Ping::new(255);
        let pong = Pong::from_ping(&ping);
        assert_eq!(pong.data(), 0); // 255 + 1 wraps to 0
    }

    #[tokio::test]
    async fn test_to_stream_and_from_stream() {
        let original_pong = Pong::new(123);

        // Write to Vec
        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            original_pong.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Read from Vec
        let mut reader = BufReader::new(&buffer[..]);
        let parsed_pong = Pong::from_stream(&mut reader).await.unwrap();

        assert_eq!(original_pong.data(), parsed_pong.data());
    }

    #[tokio::test]
    async fn test_serialization_format() {
        let pong = Pong::new(42);
        let mut buffer = vec![];

        {
            let mut writer = BufWriter::new(&mut buffer);
            pong.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer[0], Pong::OPCODE);
        assert_eq!(buffer[1], 42);
    }

    #[tokio::test]
    async fn test_invalid_opcode() {
        let buffer = [99, 42]; // Wrong opcode
        let mut reader = BufReader::new(&buffer[..]);

        let result = Pong::from_stream(&mut reader).await;
        assert!(result.is_err());
    }
}
