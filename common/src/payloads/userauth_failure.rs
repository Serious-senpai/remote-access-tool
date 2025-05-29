use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::utils::{read_string, write_string};
use super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct UserauthFailure {
    pub methods: Vec<String>,
    pub partial_success: bool,
}

#[async_trait]
impl PayloadFormat for UserauthFailure {
    const OPCODE: u8 = 51;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let methods = read_string(stream).await?;
        let methods = String::from_utf8(methods)?
            .split(',')
            .map(String::from)
            .collect();

        let partial_success = stream.read_u8().await? != 0;

        Ok(Self {
            methods,
            partial_success,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        write_string(stream, &self.methods.join(",").as_bytes()).await?;
        stream
            .write_u8(if self.partial_success { 1 } else { 0 })
            .await?;
        Ok(())
    }
}
