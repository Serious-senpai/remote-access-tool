use std::error::Error;

use tokio::io::AsyncWriteExt;

use super::super::utils::{read_string, write_string};
use super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct ServiceRequest {
    pub service_name: String,
}

impl PayloadFormat for ServiceRequest {
    const OPCODE: u8 = 5;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
        S: tokio::io::AsyncReadExt + Unpin,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let service_name = read_string(stream).await?;
        let service_name = String::from_utf8(service_name)?;

        Ok(Self { service_name })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        Self: Sized,
        S: AsyncWriteExt + Unpin,
    {
        stream.write_u8(Self::OPCODE).await?;
        write_string(stream, self.service_name.as_bytes()).await?;
        Ok(())
    }
}
