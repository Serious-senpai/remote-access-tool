use std::error::Error;
use std::path::PathBuf;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::super::errors::RuntimeError;
use super::super::super::utils::{read_string, write_string};
use super::super::PayloadFormat;

#[derive(Debug, Clone)]
pub enum Request {
    Pwd,
    Ls(PathBuf),
    Cd(PathBuf),
}

impl Request {
    fn opcode(&self) -> u8 {
        match self {
            Request::Pwd => 0,
            Request::Ls(_) => 1,
            Request::Cd(_) => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Command {
    _request_id: u32,
    _command: Request,
}

#[async_trait]
impl PayloadFormat for Command {
    const OPCODE: u8 = 192;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let request_id = stream.read_u32().await?;
        let command = match stream.read_u8().await? {
            0 => Request::Pwd,
            1 => {
                let path = read_string(stream).await?;
                Request::Ls(PathBuf::from(String::from_utf8(path)?))
            }
            2 => {
                let path = read_string(stream).await?;
                Request::Cd(PathBuf::from(String::from_utf8(path)?))
            }
            opcode => Err(RuntimeError::new(format!(
                "Unknown command opcode {}",
                opcode
            )))?,
        };

        Ok(Self {
            _request_id: request_id,
            _command: command,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_u32(self._request_id).await?;
        stream.write_u8(self._command.opcode()).await?;

        match &self._command {
            Request::Pwd => {}
            Request::Ls(path) => {
                write_string(stream, path.to_str().unwrap_or("").as_bytes()).await?;
            }
            Request::Cd(path) => {
                write_string(stream, path.to_str().unwrap_or("").as_bytes()).await?;
            }
        }

        Ok(())
    }
}

impl Command {
    pub fn new(request_id: u32, command: Request) -> Self {
        Self {
            _request_id: request_id,
            _command: command,
        }
    }

    pub fn request_id(&self) -> u32 {
        self._request_id
    }

    pub fn command(&self) -> &Request {
        &self._command
    }
}
