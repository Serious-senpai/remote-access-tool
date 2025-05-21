use tokio::io::AsyncWriteExt;

use crate::payloads::format::PayloadFormat;
use crate::utils::{read_string, write_string};

#[derive(Debug, Clone)]
pub struct KexEcdhInit {
    pub public_key: Vec<u8>,
}

impl PayloadFormat for KexEcdhInit {
    const OPCODE: u8 = 30;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized,
        S: tokio::io::AsyncReadExt + Unpin,
    {
        let opcode = stream.read_u8().await?;
        Self::check_opcode(opcode)?;

        let public_key = read_string(stream).await?;

        Ok(Self { public_key })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn std::error::Error>>
    where
        Self: Sized,
        S: AsyncWriteExt + Unpin,
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
}
