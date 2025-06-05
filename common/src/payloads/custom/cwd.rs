use std::env::current_dir;
use std::error::Error;
use std::path::PathBuf;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::super::utils::{read_string, write_string};
use super::super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct Cwd {
    _cwd: PathBuf,
}

#[async_trait]
impl PayloadFormat for Cwd {
    const OPCODE: u8 = 192;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let cwd = read_string(stream).await?;
        let cwd = PathBuf::from(String::from_utf8(cwd)?);

        Ok(Self { _cwd: cwd })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        write_string(stream, self._cwd.to_str().unwrap_or("").as_bytes()).await?;
        Ok(())
    }
}

impl Default for Cwd {
    fn default() -> Self {
        Self::new()
    }
}

impl Cwd {
    pub fn new() -> Self {
        Self {
            _cwd: current_dir().unwrap_or(PathBuf::from(".")),
        }
    }

    pub fn cwd(&self) -> &PathBuf {
        &self._cwd
    }
}
