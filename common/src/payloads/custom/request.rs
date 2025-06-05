use std::error::Error;
use std::path::PathBuf;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::super::errors::RuntimeError;
use super::super::super::utils::{read_string, write_string};
use super::super::PayloadFormat;

#[derive(Debug, Clone)]
pub enum Command {
    Pwd,
    Ls(Option<PathBuf>),
    Cd(PathBuf),
}

impl Command {
    fn opcode(&self) -> u8 {
        match self {
            Command::Pwd => 0,
            Command::Ls(_) => 1,
            Command::Cd(_) => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    _command: Command,
}

#[async_trait]
impl PayloadFormat for Request {
    const OPCODE: u8 = 195;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let command = match stream.read_u8().await? {
            0 => Command::Pwd,
            1 => {
                let path = read_string(stream).await?;
                Command::Ls(if path.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(String::from_utf8(path)?))
                })
            }
            2 => {
                let path = read_string(stream).await?;
                Command::Cd(PathBuf::from(String::from_utf8(path)?))
            }
            opcode => Err(RuntimeError::new(format!(
                "Unknown command opcode {}",
                opcode
            )))?,
        };

        Ok(Self { _command: command })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_u8(self._command.opcode()).await?;
        match &self._command {
            Command::Pwd => {}
            Command::Ls(path) => {
                let path = path.clone().unwrap_or_default();
                write_string(stream, path.to_str().unwrap_or("").as_bytes()).await?;
            }
            Command::Cd(path) => {
                write_string(stream, path.to_str().unwrap_or("").as_bytes()).await?;
            }
        }

        Ok(())
    }
}

impl Request {
    pub fn new(command: Command) -> Self {
        Self { _command: command }
    }

    pub fn command(&self) -> &Command {
        &self._command
    }
}
