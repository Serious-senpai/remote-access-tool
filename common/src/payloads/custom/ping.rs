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

#[cfg(test)]
mod tests {
    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_ping_roundtrip() {
        let original_ping = Ping::new(42);

        // Write to Vec
        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            original_ping.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Read from Vec
        let mut reader = BufReader::new(buffer.as_slice());
        let parsed_ping = Ping::from_stream(&mut reader).await.unwrap();

        assert_eq!(original_ping.data(), parsed_ping.data());
    }

    #[tokio::test]
    async fn test_ping_opcode() {
        let ping = Ping::new(123);
        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            ping.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        assert_eq!(buffer[0], Ping::OPCODE);
        assert_eq!(buffer[1], 123);
    }

    #[tokio::test]
    async fn test_ping_data_preservation() {
        for data_value in [0, 1, 127, 255] {
            let ping = Ping::new(data_value);
            let mut buffer = vec![];
            {
                let mut writer = BufWriter::new(&mut buffer);
                ping.to_stream(&mut writer).await.unwrap();
                writer.flush().await.unwrap();
            }

            let mut reader = BufReader::new(buffer.as_slice());
            let parsed_ping = Ping::from_stream(&mut reader).await.unwrap();

            assert_eq!(ping.data(), parsed_ping.data());
            assert_eq!(parsed_ping.data(), data_value);
        }
    }
}
