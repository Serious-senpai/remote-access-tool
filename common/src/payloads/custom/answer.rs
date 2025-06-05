use std::error::Error;
use std::path::PathBuf;
use std::time::SystemTime;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::super::errors::RuntimeError;
use super::super::super::utils::{read_string, write_string};
use super::super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct EntryMetadata {
    pub created_at: SystemTime,
    pub modified_at: SystemTime,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub file_name: String,
    pub file_type: String,
    pub metadata: Option<EntryMetadata>,
}

#[derive(Debug, Clone)]
pub enum Response {
    Pwd(PathBuf),
    Ls(Vec<Entry>),
    Cd(PathBuf, String),
}

impl Response {
    fn opcode(&self) -> u8 {
        match self {
            Response::Pwd(..) => 0,
            Response::Ls(..) => 1,
            Response::Cd(..) => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Answer {
    _request_id: u32,
    _answer: Response,
}

#[async_trait]
impl PayloadFormat for Answer {
    const OPCODE: u8 = 192;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let request_id = stream.read_u32().await?;
        let answer = match stream.read_u8().await? {
            0 => {
                let path = read_string(stream).await?;
                Response::Pwd(PathBuf::from(String::from_utf8(path)?))
            }
            1 => {
                let mut entries = vec![];
                let entries_count = stream.read_u32().await? as usize;
                for _ in 0..entries_count {
                    let file_name = String::from_utf8(read_string(stream).await?)?;
                    let file_type = String::from_utf8(read_string(stream).await?)?;
                    let has_metadata = stream.read_u8().await? != 0;
                    let metadata = if has_metadata {
                        Some(EntryMetadata {
                            created_at: SystemTime::UNIX_EPOCH
                                + std::time::Duration::from_secs(stream.read_u64().await?),
                            modified_at: SystemTime::UNIX_EPOCH
                                + std::time::Duration::from_secs(stream.read_u64().await?),
                            size: stream.read_u64().await?,
                        })
                    } else {
                        None
                    };

                    entries.push(Entry {
                        file_name,
                        file_type,
                        metadata,
                    });
                }

                Response::Ls(entries)
            }
            2 => {
                let path = PathBuf::from(String::from_utf8(read_string(stream).await?)?);
                let message = String::from_utf8(read_string(stream).await?)?;
                Response::Cd(path, message)
            }
            opcode => Err(RuntimeError::new(format!(
                "Unknown answer opcode {}",
                opcode
            )))?,
        };

        Ok(Self {
            _request_id: request_id,
            _answer: answer,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_u32(self._request_id).await?;
        stream.write_u8(self._answer.opcode()).await?;

        match &self._answer {
            Response::Pwd(path) => {
                write_string(stream, path.to_str().unwrap_or("").as_bytes()).await?;
            }
            Response::Ls(entries) => {
                stream.write_u32(entries.len() as u32).await?;
                for entry in entries {
                    write_string(stream, entry.file_name.as_bytes()).await?;
                    write_string(stream, entry.file_type.as_bytes()).await?;
                    match &entry.metadata {
                        Some(metadata) => {
                            stream.write_u8(1).await?;
                            stream
                                .write_u64(
                                    metadata
                                        .created_at
                                        .duration_since(SystemTime::UNIX_EPOCH)
                                        .map_or(0, |d| d.as_secs()),
                                )
                                .await?;
                            stream
                                .write_u64(
                                    metadata
                                        .modified_at
                                        .duration_since(SystemTime::UNIX_EPOCH)
                                        .map_or(0, |d| d.as_secs()),
                                )
                                .await?;
                            stream.write_u64(metadata.size).await?;
                        }
                        None => stream.write_u8(0).await?,
                    }
                }
            }
            Response::Cd(path, message) => {
                write_string(stream, path.to_str().unwrap_or("").as_bytes()).await?;
                write_string(stream, message.as_bytes()).await?;
            }
        }

        Ok(())
    }
}

impl Answer {
    pub fn new(request_id: u32, answer: Response) -> Self {
        Self {
            _request_id: request_id,
            _answer: answer,
        }
    }

    pub fn request_id(&self) -> u32 {
        self._request_id
    }

    pub fn answer(&self) -> &Response {
        &self._answer
    }
}
