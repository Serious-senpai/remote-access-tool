use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::payloads::PayloadFormat;
use crate::utils::{read_string, write_string};

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

#[cfg(test)]
mod tests {
    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_ignore_roundtrip() {
        let original_data = vec![1, 2, 3, 4, 5];
        let ignore = Ignore::new(original_data.clone());

        // Write to Vec
        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            ignore.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Read from Vec
        let mut reader = BufReader::new(buffer.as_slice());
        let parsed_ignore = Ignore::from_stream(&mut reader).await.unwrap();

        assert_eq!(ignore.data(), parsed_ignore.data());
        assert_eq!(original_data, parsed_ignore.data());
    }

    #[tokio::test]
    async fn test_ignore_empty_data() {
        let empty_data = vec![];
        let ignore = Ignore::new(empty_data.clone());

        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            ignore.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let parsed_ignore = Ignore::from_stream(&mut reader).await.unwrap();

        assert_eq!(empty_data, parsed_ignore.data());
    }

    #[tokio::test]
    async fn test_ignore_large_data() {
        let large_data = vec![42; 1000];
        let ignore = Ignore::new(large_data.clone());

        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            ignore.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let parsed_ignore = Ignore::from_stream(&mut reader).await.unwrap();

        assert_eq!(large_data, parsed_ignore.data());
    }
}
