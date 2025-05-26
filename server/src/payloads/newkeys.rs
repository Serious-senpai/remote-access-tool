use std::error::Error;

use tokio::io::AsyncWriteExt;

use super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct NewKeys {}

impl PayloadFormat for NewKeys {
    const OPCODE: u8 = 21;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
        S: tokio::io::AsyncReadExt + Unpin,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        Ok(Self {})
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        Self: Sized,
        S: AsyncWriteExt + Unpin,
    {
        stream.write_u8(Self::OPCODE).await?;
        Ok(())
    }
}
