use std::error::Error;
use std::path::PathBuf;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::super::utils::{read_string, write_string};
use super::super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct Cwd {
    cwd: PathBuf,
}

#[async_trait]
impl PayloadFormat for Cwd {
    const OPCODE: u8 = 193;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let cwd = read_string(stream).await?;
        let cwd = PathBuf::from(String::from_utf8(cwd)?);

        Ok(Self { cwd })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        write_string(stream, self.cwd.to_str().unwrap_or("").as_bytes()).await?;
        Ok(())
    }
}

impl Cwd {
    pub fn new(cwd: PathBuf) -> Self {
        Self {
            cwd: cwd.canonicalize().unwrap_or(cwd),
        }
    }

    pub fn cwd(&self) -> &PathBuf {
        &self.cwd
    }
}
