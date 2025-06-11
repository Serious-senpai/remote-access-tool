use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::payloads::PayloadFormat;
use crate::utils::{read_string, write_string};

#[derive(Debug, Clone)]
pub struct KexEcdhInit {
    public_key: Vec<u8>,
}

#[async_trait]
impl PayloadFormat for KexEcdhInit {
    const OPCODE: u8 = 30;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let public_key = read_string(stream).await?;

        Ok(Self { public_key })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        write_string(stream, &self.public_key).await?;

        Ok(())
    }
}

impl KexEcdhInit {
    pub fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_kex_ecdh_init_roundtrip() {
        let public_key = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let payload = KexEcdhInit::new(public_key.clone());

        // Write to Vec
        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            payload.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Read from Vec
        let mut reader = BufReader::new(buffer.as_slice());
        let parsed_payload = KexEcdhInit::from_stream(&mut reader).await.unwrap();

        assert_eq!(payload.public_key(), parsed_payload.public_key());
    }

    #[tokio::test]
    async fn test_kex_ecdh_init_empty_public_key() {
        let public_key = vec![];
        let payload = KexEcdhInit::new(public_key.clone());

        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            payload.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let parsed_payload = KexEcdhInit::from_stream(&mut reader).await.unwrap();

        assert_eq!(payload.public_key(), parsed_payload.public_key());
        assert!(parsed_payload.public_key().is_empty());
    }

    #[tokio::test]
    async fn test_kex_ecdh_init_large_public_key() {
        let public_key = vec![0xFF; 1024];
        let payload = KexEcdhInit::new(public_key.clone());

        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            payload.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let parsed_payload = KexEcdhInit::from_stream(&mut reader).await.unwrap();

        assert_eq!(payload.public_key(), parsed_payload.public_key());
    }

    #[tokio::test]
    async fn test_kex_ecdh_init_opcode_verification() {
        let public_key = vec![1, 2, 3, 4];
        let payload = KexEcdhInit::new(public_key);

        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            payload.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Verify the opcode is written correctly
        assert_eq!(buffer[0], KexEcdhInit::OPCODE);
    }
}
