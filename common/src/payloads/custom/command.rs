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
    Download(PathBuf),
    Cancel(u32),
    DownloadAck(u32, u64),
}

impl Request {
    fn opcode(&self) -> u8 {
        match self {
            Request::Pwd => 0,
            Request::Ls(..) => 1,
            Request::Cd(..) => 2,
            Request::Download(..) => 3,
            Request::Cancel(..) => 4,
            Request::DownloadAck(..) => 5,
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
            3 => {
                let path = read_string(stream).await?;
                Request::Download(PathBuf::from(String::from_utf8(path)?))
            }
            4 => {
                let request_id = stream.read_u32().await?;
                Request::Cancel(request_id)
            }
            5 => {
                let request_id = stream.read_u32().await?;
                let received = stream.read_u64().await?;
                Request::DownloadAck(request_id, received)
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
            Request::Download(path) => {
                write_string(stream, path.to_str().unwrap_or("").as_bytes()).await?;
            }
            Request::Cancel(request_id) => {
                stream.write_u32(*request_id).await?;
            }
            Request::DownloadAck(request_id, received) => {
                stream.write_u32(*request_id).await?;
                stream.write_u64(*received).await?;
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
