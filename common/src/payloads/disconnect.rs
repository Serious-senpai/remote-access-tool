use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::payloads::PayloadFormat;
use crate::utils::{read_string, write_string};

#[derive(Debug, Clone)]
pub struct Disconnect {
    reason_code: u32,
    description: String,
    language_tag: String,
}

#[async_trait]
impl PayloadFormat for Disconnect {
    const OPCODE: u8 = 1;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let reason_code = stream.read_u32().await?;
        let description = read_string(stream).await?;
        let description = String::from_utf8(description)?;

        let language_tag = read_string(stream).await?;
        let language_tag = String::from_utf8(language_tag)?;

        Ok(Self {
            reason_code,
            description,
            language_tag,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_u32(self.reason_code).await?;
        write_string(stream, self.description.as_bytes()).await?;
        write_string(stream, self.language_tag.as_bytes()).await?;
        Ok(())
    }
}

impl Disconnect {
    pub fn new(
        reason_code: u32,
        description: impl Into<String>,
        language_tag: impl Into<String>,
    ) -> Self {
        Self {
            reason_code,
            description: description.into(),
            language_tag: language_tag.into(),
        }
    }

    pub fn reason_code(&self) -> u32 {
        self.reason_code
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn language_tag(&self) -> &str {
        &self.language_tag
    }
}
#[cfg(test)]
mod tests {
    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_disconnect_roundtrip() {
        let original = Disconnect::new(42, "Connection lost", "en-US");

        // Write to Vec
        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            original.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Read from Vec
        let mut reader = BufReader::new(buffer.as_slice());
        let parsed = Disconnect::from_stream(&mut reader).await.unwrap();

        assert_eq!(original.reason_code(), parsed.reason_code());
        assert_eq!(original.description(), parsed.description());
        assert_eq!(original.language_tag(), parsed.language_tag());
    }

    #[tokio::test]
    async fn test_disconnect_empty_strings() {
        let original = Disconnect::new(0, "", "");

        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            original.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let parsed = Disconnect::from_stream(&mut reader).await.unwrap();

        assert_eq!(original.reason_code(), parsed.reason_code());
        assert_eq!(original.description(), parsed.description());
        assert_eq!(original.language_tag(), parsed.language_tag());
    }

    #[tokio::test]
    async fn test_disconnect_max_values() {
        let original = Disconnect::new(
            u32::MAX,
            "Very long description".repeat(100),
            "en-US-x-test",
        );

        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            original.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let parsed = Disconnect::from_stream(&mut reader).await.unwrap();

        assert_eq!(original.reason_code(), parsed.reason_code());
        assert_eq!(original.description(), parsed.description());
        assert_eq!(original.language_tag(), parsed.language_tag());
    }

    #[tokio::test]
    async fn test_disconnect_opcode_verification() {
        let disconnect = Disconnect::new(1, "test", "en");

        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            disconnect.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Verify opcode is written correctly
        assert_eq!(buffer[0], Disconnect::OPCODE);
    }
}
