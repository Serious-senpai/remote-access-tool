use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use log::error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::errors::RuntimeError;
use crate::payloads::custom::query::Query;
use crate::payloads::custom::request::Request;
use crate::payloads::PayloadFormat;
use crate::utils::{read_address, read_string, write_address, write_string};

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
pub struct ClientEntry {
    pub addr: SocketAddr,
    pub version: String,
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u64,
    pub accumulated_cpu_time: u64,
    pub cmd: String,
    pub cpu_usage: f32,
    pub memory: u64,
    pub name: String,
    pub run_time: u64,
}

#[derive(Debug, Clone)]
pub enum ResponseType {
    Pwd { path: PathBuf },
    Ls { entries: Vec<Entry> },
    DownloadChunk { total: u64, data: Vec<u8> },
    Error { message: String },
    Success,
    ClientLs { clients: Vec<ClientEntry> },
    Ps { processes: Vec<ProcessEntry> },
}

impl ResponseType {
    fn opcode(&self) -> u8 {
        match self {
            Self::Pwd { .. } => 0,
            Self::Ls { .. } => 1,
            Self::DownloadChunk { .. } => 3,
            Self::Error { .. } => 4,
            Self::Success => 5,
            Self::ClientLs { .. } => 6,
            Self::Ps { .. } => 7,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    _request_id: u32,
    _src: SocketAddr,
    _dest: SocketAddr,
    _rtype: ResponseType,
}

#[async_trait]
impl PayloadFormat for Response {
    const OPCODE: u8 = 192;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let request_id = stream.read_u32().await?;
        let src = read_address(stream).await?;
        let dest = read_address(stream).await?;

        let rtype = match stream.read_u8().await? {
            0 => {
                let path = PathBuf::from(String::from_utf8(read_string(stream).await?)?);
                ResponseType::Pwd { path }
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
                                + Duration::from_secs(stream.read_u64().await?),
                            modified_at: SystemTime::UNIX_EPOCH
                                + Duration::from_secs(stream.read_u64().await?),
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

                ResponseType::Ls { entries }
            }
            3 => {
                let total = stream.read_u64().await?;
                let data = read_string(stream).await?;
                ResponseType::DownloadChunk { total, data }
            }
            4 => {
                let message = String::from_utf8(read_string(stream).await?)?;
                ResponseType::Error { message }
            }
            5 => ResponseType::Success,
            6 => {
                let mut clients = vec![];
                let clients_count = stream.read_u32().await? as usize;
                for _ in 0..clients_count {
                    let addr = String::from_utf8(read_string(stream).await?)?;
                    let addr = SocketAddr::from_str(&addr)?;
                    let version = String::from_utf8(read_string(stream).await?)?;
                    let is_admin = stream.read_u8().await? != 0;

                    clients.push(ClientEntry {
                        addr,
                        version,
                        is_admin,
                    });
                }

                ResponseType::ClientLs { clients }
            }
            7 => {
                let mut processes = vec![];
                let processes_count = stream.read_u64().await?;

                for _ in 0..processes_count {
                    let pid = stream.read_u64().await?;
                    let accumulated_cpu_time = stream.read_u64().await?;
                    let cmd = String::from_utf8(read_string(stream).await?)?;
                    let cpu_usage = stream.read_f32().await?;
                    let memory = stream.read_u64().await?;
                    let name = String::from_utf8(read_string(stream).await?)?;
                    let run_time = stream.read_u64().await?;

                    processes.push(ProcessEntry {
                        pid,
                        accumulated_cpu_time,
                        cmd,
                        cpu_usage,
                        memory,
                        name,
                        run_time,
                    });
                }

                ResponseType::Ps { processes }
            }
            opcode => Err(RuntimeError::new(format!(
                "Unknown response opcode {}",
                opcode
            )))?,
        };

        Ok(Self {
            _request_id: request_id,
            _src: src,
            _dest: dest,
            _rtype: rtype,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_u32(self._request_id).await?;
        write_address(stream, &self._src).await?;
        write_address(stream, &self._dest).await?;

        stream.write_u8(self._rtype.opcode()).await?;

        match &self._rtype {
            ResponseType::Pwd { path } => {
                write_string(stream, path.to_str().unwrap_or("").as_bytes()).await?;
            }
            ResponseType::Ls { entries } => {
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
            ResponseType::DownloadChunk { total, data } => {
                stream.write_u64(*total).await?;
                write_string(stream, data).await?;
            }
            ResponseType::Error { message } => {
                write_string(stream, message.as_bytes()).await?;
            }
            ResponseType::Success => (),
            ResponseType::ClientLs { clients } => {
                stream.write_u32(clients.len() as u32).await?;
                for client in clients {
                    write_string(stream, client.addr.to_string().as_bytes()).await?;
                    write_string(stream, client.version.as_bytes()).await?;
                    stream.write_u8(u8::from(client.is_admin)).await?;
                }
            }
            ResponseType::Ps { processes } => {
                stream.write_u64(processes.len() as u64).await?;
                for process in processes {
                    stream.write_u64(process.pid).await?;
                    stream.write_u64(process.accumulated_cpu_time).await?;
                    write_string(stream, process.cmd.as_bytes()).await?;
                    stream.write_f32(process.cpu_usage).await?;
                    stream.write_u64(process.memory).await?;
                    write_string(stream, process.name.as_bytes()).await?;
                    stream.write_u64(process.run_time).await?;
                }
            }
        }

        Ok(())
    }
}

const _DUMMY_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

impl Response {
    pub fn new(request_id: u32, src: SocketAddr, dest: SocketAddr, rtype: ResponseType) -> Self {
        Self {
            _request_id: request_id,
            _src: src,
            _dest: dest,
            _rtype: rtype,
        }
    }

    pub fn response_request(command: &Request, rtype: ResponseType) -> Self {
        Self::new(command.request_id(), command.src(), command.dest(), rtype)
    }

    pub fn response_query(query: &Query, rtype: ResponseType) -> Self {
        Self::new(query.request_id(), _DUMMY_ADDR, _DUMMY_ADDR, rtype)
    }

    pub fn error_and_log(
        request_id: u32,
        src: SocketAddr,
        dest: SocketAddr,
        message: impl Into<String>,
    ) -> Self {
        let message = message.into();
        error!("{}", message);
        Self::new(request_id, src, dest, ResponseType::Error { message })
    }

    pub fn request_id(&self) -> u32 {
        self._request_id
    }

    pub fn src(&self) -> SocketAddr {
        self._src
    }

    pub fn dest(&self) -> SocketAddr {
        self._dest
    }

    pub fn rtype(&self) -> &ResponseType {
        &self._rtype
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{BufReader, BufWriter};

    use super::*;

    async fn test_round_trip(response: Response) {
        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            response.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let parsed = Response::from_stream(&mut reader).await.unwrap();

        assert_eq!(response.request_id(), parsed.request_id());
        assert_eq!(response.src(), parsed.src());
        assert_eq!(response.dest(), parsed.dest());

        match (response.rtype(), parsed.rtype()) {
            (ResponseType::Pwd { path: p1 }, ResponseType::Pwd { path: p2 }) => {
                assert_eq!(p1, p2);
            }
            (ResponseType::Ls { entries: e1 }, ResponseType::Ls { entries: e2 }) => {
                assert_eq!(e1.len(), e2.len());
                for (entry1, entry2) in e1.iter().zip(e2.iter()) {
                    assert_eq!(entry1.file_name, entry2.file_name);
                    assert_eq!(entry1.file_type, entry2.file_type);
                    match (&entry1.metadata, &entry2.metadata) {
                        (Some(m1), Some(m2)) => {
                            assert_eq!(m1.size, m2.size);
                            assert_eq!(
                                m1.created_at
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                m2.created_at
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs()
                            );
                            assert_eq!(
                                m1.modified_at
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                m2.modified_at
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs()
                            );
                        }
                        (None, None) => {}
                        _ => panic!("Metadata mismatch"),
                    }
                }
            }
            (
                ResponseType::DownloadChunk {
                    total: t1,
                    data: d1,
                },
                ResponseType::DownloadChunk {
                    total: t2,
                    data: d2,
                },
            ) => {
                assert_eq!(t1, t2);
                assert_eq!(d1, d2);
            }
            (ResponseType::Error { message: m1 }, ResponseType::Error { message: m2 }) => {
                assert_eq!(m1, m2);
            }
            (ResponseType::Success, ResponseType::Success) => {}
            (ResponseType::ClientLs { clients: c1 }, ResponseType::ClientLs { clients: c2 }) => {
                assert_eq!(c1.len(), c2.len());
                for (client1, client2) in c1.iter().zip(c2.iter()) {
                    assert_eq!(client1.addr, client2.addr);
                    assert_eq!(client1.version, client2.version);
                    assert_eq!(client1.is_admin, client2.is_admin);
                }
            }
            (ResponseType::Ps { processes: p1 }, ResponseType::Ps { processes: p2 }) => {
                assert_eq!(p1.len(), p2.len());
                for (proc1, proc2) in p1.iter().zip(p2.iter()) {
                    assert_eq!(proc1.pid, proc2.pid);
                    assert_eq!(proc1.accumulated_cpu_time, proc2.accumulated_cpu_time);
                    assert_eq!(proc1.cmd, proc2.cmd);
                    assert_eq!(proc1.cpu_usage, proc2.cpu_usage);
                    assert_eq!(proc1.memory, proc2.memory);
                    assert_eq!(proc1.name, proc2.name);
                    assert_eq!(proc1.run_time, proc2.run_time);
                }
            }
            _ => panic!("Response type mismatch"),
        }
    }

    #[tokio::test]
    async fn test_pwd_response() {
        let response = Response::new(
            123,
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:9090".parse().unwrap(),
            ResponseType::Pwd {
                path: PathBuf::from("/home/user"),
            },
        );
        test_round_trip(response).await;
    }

    #[tokio::test]
    async fn test_ls_response_with_metadata() {
        let metadata = EntryMetadata {
            created_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1234567890),
            modified_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1234567900),
            size: 1024,
        };

        let response = Response::new(
            456,
            "192.168.1.1:3000".parse().unwrap(),
            "192.168.1.2:4000".parse().unwrap(),
            ResponseType::Ls {
                entries: vec![
                    Entry {
                        file_name: "file1.txt".to_string(),
                        file_type: "file".to_string(),
                        metadata: Some(metadata.clone()),
                    },
                    Entry {
                        file_name: "dir1".to_string(),
                        file_type: "directory".to_string(),
                        metadata: None,
                    },
                ],
            },
        );
        test_round_trip(response).await;
    }

    #[tokio::test]
    async fn test_download_chunk_response() {
        let response = Response::new(
            789,
            "10.0.0.1:5000".parse().unwrap(),
            "10.0.0.2:6000".parse().unwrap(),
            ResponseType::DownloadChunk {
                total: 2048,
                data: vec![0x41, 0x42, 0x43, 0x44],
            },
        );
        test_round_trip(response).await;
    }

    #[tokio::test]
    async fn test_error_response() {
        let response = Response::new(
            999,
            "172.16.0.1:7000".parse().unwrap(),
            "172.16.0.2:8000".parse().unwrap(),
            ResponseType::Error {
                message: "Something went wrong".to_string(),
            },
        );
        test_round_trip(response).await;
    }

    #[tokio::test]
    async fn test_success_response() {
        let response = Response::new(
            111,
            "127.0.0.1:1111".parse().unwrap(),
            "127.0.0.1:2222".parse().unwrap(),
            ResponseType::Success,
        );
        test_round_trip(response).await;
    }

    #[tokio::test]
    async fn test_client_ls_response() {
        let response = Response::new(
            222,
            "0.0.0.0:0".parse().unwrap(),
            "255.255.255.255:65535".parse().unwrap(),
            ResponseType::ClientLs {
                clients: vec![
                    ClientEntry {
                        addr: "192.168.1.100:8080".parse().unwrap(),
                        version: "1.0.0".to_string(),
                        is_admin: true,
                    },
                    ClientEntry {
                        addr: "192.168.1.101:8081".parse().unwrap(),
                        version: "1.1.0".to_string(),
                        is_admin: false,
                    },
                ],
            },
        );
        test_round_trip(response).await;
    }

    #[tokio::test]
    async fn test_ps_response() {
        let response = Response::new(
            333,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1:54321".parse().unwrap(),
            ResponseType::Ps {
                processes: vec![
                    ProcessEntry {
                        pid: 1234,
                        accumulated_cpu_time: 500000,
                        cmd: "/usr/bin/firefox".to_string(),
                        cpu_usage: 15.5,
                        memory: 1073741824,
                        name: "firefox".to_string(),
                        run_time: 3600,
                    },
                    ProcessEntry {
                        pid: 5678,
                        accumulated_cpu_time: 100000,
                        cmd: "/bin/bash".to_string(),
                        cpu_usage: 0.1,
                        memory: 8388608,
                        name: "bash".to_string(),
                        run_time: 7200,
                    },
                ],
            },
        );
        test_round_trip(response).await;
    }

    #[tokio::test]
    async fn test_empty_collections() {
        // Test empty ls
        let response = Response::new(
            444,
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:2000".parse().unwrap(),
            ResponseType::Ls { entries: vec![] },
        );
        test_round_trip(response).await;

        // Test empty client list
        let response = Response::new(
            555,
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:2000".parse().unwrap(),
            ResponseType::ClientLs { clients: vec![] },
        );
        test_round_trip(response).await;

        // Test empty process list
        let response = Response::new(
            666,
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:2000".parse().unwrap(),
            ResponseType::Ps { processes: vec![] },
        );
        test_round_trip(response).await;
    }
}
