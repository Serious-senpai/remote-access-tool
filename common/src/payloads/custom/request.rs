use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::errors::RuntimeError;
use crate::payloads::PayloadFormat;
use crate::utils::{read_address, read_string, write_address, write_string};

#[derive(Debug, Clone)]
pub enum RequestType {
    Pwd,
    Ls { path: PathBuf },
    Cd { path: PathBuf },
    Download { path: PathBuf },
    Ps,
    Kill { pid: u64, signal: i32 },
    Rm { path: PathBuf },
}

impl RequestType {
    fn opcode(&self) -> u8 {
        match self {
            Self::Pwd => 0,
            Self::Ls { .. } => 1,
            Self::Cd { .. } => 2,
            Self::Download { .. } => 3,
            Self::Ps => 5,
            Self::Kill { .. } => 6,
            Self::Rm { .. } => 7,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    _request_id: u32,
    _src: SocketAddr,
    _dest: SocketAddr,
    _rtype: RequestType,
}

#[async_trait]
impl PayloadFormat for Request {
    const OPCODE: u8 = 193;

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
            0 => RequestType::Pwd,
            1 => {
                let path = PathBuf::from(String::from_utf8(read_string(stream).await?)?);
                RequestType::Ls { path }
            }
            2 => {
                let path = PathBuf::from(String::from_utf8(read_string(stream).await?)?);
                RequestType::Cd { path }
            }
            3 => {
                let path = PathBuf::from(String::from_utf8(read_string(stream).await?)?);
                RequestType::Download { path }
            }
            5 => RequestType::Ps,
            6 => {
                let pid = stream.read_u64().await?;
                let signal = stream.read_i32().await?;
                RequestType::Kill { pid, signal }
            }
            7 => {
                let path = PathBuf::from(String::from_utf8(read_string(stream).await?)?);
                RequestType::Rm { path }
            }
            opcode => Err(RuntimeError::new(format!(
                "Unknown request opcode {}",
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

        let err = RuntimeError::new("Invalid path provided");
        match &self._rtype {
            RequestType::Ls { path } => {
                write_string(stream, path.to_str().ok_or(err)?.as_bytes()).await?;
            }
            RequestType::Cd { path } => {
                write_string(stream, path.to_str().ok_or(err)?.as_bytes()).await?;
            }
            RequestType::Download { path } => {
                write_string(stream, path.to_str().ok_or(err)?.as_bytes()).await?;
            }
            RequestType::Kill { pid, signal } => {
                stream.write_u64(*pid).await?;
                stream.write_i32(*signal).await?;
            }
            RequestType::Rm { path } => {
                write_string(stream, path.to_str().ok_or(err)?.as_bytes()).await?;
            }
            RequestType::Pwd | RequestType::Ps => (),
        }

        Ok(())
    }
}

impl Request {
    pub fn new(request_id: u32, src: SocketAddr, dest: SocketAddr, rtype: RequestType) -> Self {
        Self {
            _request_id: request_id,
            _src: src,
            _dest: dest,
            _rtype: rtype,
        }
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

    pub fn rtype(&self) -> &RequestType {
        &self._rtype
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_request_pwd_roundtrip() {
        let request = Request::new(
            42,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9000),
            RequestType::Pwd,
        );

        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            request.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let parsed = Request::from_stream(&mut reader).await.unwrap();

        assert_eq!(request.request_id(), parsed.request_id());
        assert_eq!(request.src(), parsed.src());
        assert_eq!(request.dest(), parsed.dest());
        matches!(parsed.rtype(), RequestType::Pwd);
    }

    #[tokio::test]
    async fn test_request_ls_roundtrip() {
        let request = Request::new(
            123,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 3000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 4000),
            RequestType::Ls {
                path: PathBuf::from("/home/user"),
            },
        );

        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            request.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let parsed = Request::from_stream(&mut reader).await.unwrap();

        assert_eq!(request.request_id(), parsed.request_id());
        assert_eq!(request.src(), parsed.src());
        assert_eq!(request.dest(), parsed.dest());
        if let RequestType::Ls { path } = parsed.rtype() {
            assert_eq!(path, &PathBuf::from("/home/user"));
        } else {
            panic!("Expected Ls request type");
        }
    }

    #[tokio::test]
    async fn test_request_kill_roundtrip() {
        let request = Request::new(
            999,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8000),
            RequestType::Kill {
                pid: 12345,
                signal: 9,
            },
        );

        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            request.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let parsed = Request::from_stream(&mut reader).await.unwrap();

        assert_eq!(request.request_id(), parsed.request_id());
        assert_eq!(request.src(), parsed.src());
        assert_eq!(request.dest(), parsed.dest());
        if let RequestType::Kill { pid, signal } = parsed.rtype() {
            assert_eq!(*pid, 12345);
            assert_eq!(*signal, 9);
        } else {
            panic!("Expected Kill request type");
        }
    }

    #[tokio::test]
    async fn test_request_all_types_roundtrip() {
        let test_cases = vec![
            RequestType::Pwd,
            RequestType::Ps,
            RequestType::Ls {
                path: PathBuf::from("/tmp"),
            },
            RequestType::Cd {
                path: PathBuf::from("/var/log"),
            },
            RequestType::Download {
                path: PathBuf::from("/etc/passwd"),
            },
            RequestType::Rm {
                path: PathBuf::from("/tmp/file.txt"),
            },
        ];

        for (i, rtype) in test_cases.into_iter().enumerate() {
            let request = Request::new(
                i as u32,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9000),
                rtype,
            );

            let mut buffer = vec![];
            {
                let mut writer = BufWriter::new(&mut buffer);
                request.to_stream(&mut writer).await.unwrap();
                writer.flush().await.unwrap();
            }

            let mut reader = BufReader::new(buffer.as_slice());
            let parsed = Request::from_stream(&mut reader).await.unwrap();

            assert_eq!(request.request_id(), parsed.request_id());
            assert_eq!(request.src(), parsed.src());
            assert_eq!(request.dest(), parsed.dest());
            assert_eq!(request.rtype().opcode(), parsed.rtype().opcode());
        }
    }
}
