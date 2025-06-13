use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::payloads::PayloadFormat;

#[derive(Debug, Clone)]
pub struct NewKeys;

#[async_trait]
impl PayloadFormat for NewKeys {
    const OPCODE: u8 = 21;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        Ok(Self {})
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_newkeys_roundtrip() {
        let original = NewKeys;
        let mut buffer = vec![];

        // Write to buffer
        {
            let mut writer = BufWriter::new(&mut buffer);
            original.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Read from buffer
        let mut reader = BufReader::new(&buffer[..]);
        NewKeys::from_stream(&mut reader).await.unwrap();

        // Verify opcode was written correctly
        assert_eq!(buffer[0], NewKeys::OPCODE);
        assert_eq!(buffer.len(), 1);
    }

    #[tokio::test]
    async fn test_newkeys_from_stream_correct_opcode() {
        let buffer = [NewKeys::OPCODE];
        let mut reader = BufReader::new(&buffer[..]);

        let result = NewKeys::from_stream(&mut reader).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_newkeys_from_stream_wrong_opcode() {
        let buffer = [255]; // Wrong opcode
        let mut reader = BufReader::new(&buffer[..]);

        let result = NewKeys::from_stream(&mut reader).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_newkeys_to_stream() {
        let newkeys = NewKeys;
        let mut buffer = vec![];

        {
            let mut writer = BufWriter::new(&mut buffer);
            newkeys.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        assert_eq!(buffer, vec![NewKeys::OPCODE]);
    }
}
