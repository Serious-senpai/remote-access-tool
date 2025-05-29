use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::utils::{read_string, write_string};
use super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct Disconnect {
    pub reason_code: u32,
    pub description: String,
    pub language_tag: String,
}

#[async_trait]
impl PayloadFormat for Disconnect {
    const OPCODE: u8 = 1;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
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

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
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
