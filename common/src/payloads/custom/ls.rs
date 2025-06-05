use std::error::Error;
use std::fs::read_dir;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use log::error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::super::utils::{read_string, write_string};
use super::super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct Entry {
    pub file_name: String,
    pub file_type: String,
    pub created_at: SystemTime,
    pub modified_at: SystemTime,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct ListDir {
    _entries: Vec<Entry>,
}

#[async_trait]
impl PayloadFormat for ListDir {
    const OPCODE: u8 = 192;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let n = stream.read_u32().await? as usize;
        let mut entries = vec![];
        for _ in 0..n {
            let file_name = String::from_utf8(read_string(stream).await?)?;
            let file_type = String::from_utf8(read_string(stream).await?)?;
            let created_at = SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(stream.read_u64().await?))
                .unwrap_or(SystemTime::UNIX_EPOCH);
            let modified_at = SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(stream.read_u64().await?))
                .unwrap_or(SystemTime::UNIX_EPOCH);
            let size = stream.read_u64().await?;

            entries.push(Entry {
                file_name,
                file_type,
                created_at,
                modified_at,
                size,
            });
        }

        Ok(Self { _entries: entries })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_u32(self._entries.len() as u32).await?;
        for entry in &self._entries {
            write_string(stream, entry.file_name.as_bytes()).await?;
            write_string(stream, entry.file_type.as_bytes()).await?;
            stream
                .write_u64(
                    entry
                        .created_at
                        .duration_since(SystemTime::UNIX_EPOCH)?
                        .as_secs(),
                )
                .await?;
            stream
                .write_u64(
                    entry
                        .modified_at
                        .duration_since(SystemTime::UNIX_EPOCH)?
                        .as_secs(),
                )
                .await?;
            stream.write_u64(entry.size).await?;
        }
        Ok(())
    }
}

impl ListDir {
    pub fn new(path: &PathBuf) -> Self {
        let entries = match read_dir(path) {
            Ok(entries) => {
                let mut result = vec![];
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata() {
                        result.push(Entry {
                            file_name: entry.file_name().to_string_lossy().into_owned(),
                            file_type: if metadata.is_dir() {
                                "dir".to_string()
                            } else if metadata.is_file() {
                                "file".to_string()
                            } else {
                                "symlink".to_string()
                            },
                            created_at: metadata.created().unwrap_or(SystemTime::UNIX_EPOCH),
                            modified_at: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                            size: metadata.len(),
                        })
                    }
                }

                result
            }
            Err(_) => {
                error!("Failed to read directory {:?}", path);
                vec![]
            }
        };

        Self { _entries: entries }
    }

    pub fn entries(&self) -> &[Entry] {
        &self._entries
    }
}
