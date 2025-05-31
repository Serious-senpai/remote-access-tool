use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::super::utils::{read_string, write_string};
use super::super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct Command {
    _request_id: u32,
    _command: String,
}

#[async_trait]
impl PayloadFormat for Command {
    const OPCODE: u8 = 192;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let request_id = stream.read_u32().await?;

        let command = read_string(stream).await?;
        let command = String::from_utf8(command)?;

        Ok(Self {
            _request_id: request_id,
            _command: command,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_u32(self._request_id).await?;
        write_string(stream, self._command.as_bytes()).await?;
        Ok(())
    }
}

impl Command {
    pub fn new(request_id: u32, command: impl Into<String>) -> Self {
        Self {
            _request_id: request_id,
            _command: command.into(),
        }
    }

    /// The request ID for the execution.
    pub fn request_id(&self) -> u32 {
        self._request_id
    }

    /// The command to be executed by the client.
    pub fn command(&self) -> &str {
        &self._command
    }
}
