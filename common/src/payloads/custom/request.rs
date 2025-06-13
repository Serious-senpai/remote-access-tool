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
    Ls {
        path: PathBuf,
    },
    Cd {
        path: PathBuf,
    },
    Download {
        max: u64,
        path: PathBuf,
    },
    Mkdir {
        parent: bool,
        paths: Vec<PathBuf>,
    },
    Ps,
    Kill {
        pid: u64,
        signal: i32,
    },
    Rm {
        recursive: bool,
        paths: Vec<PathBuf>,
    },
}

impl RequestType {
    fn opcode(&self) -> u8 {
        match self {
            Self::Pwd => 0,
            Self::Ls { .. } => 1,
            Self::Cd { .. } => 2,
            Self::Download { .. } => 3,
            Self::Mkdir { .. } => 4,
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
                let max = stream.read_u64().await?;
                let path = PathBuf::from(String::from_utf8(read_string(stream).await?)?);
                RequestType::Download { max, path }
            }
            4 => {
                let parent = stream.read_u8().await? == 1;

                let mut paths = vec![];
                for _ in 0..stream.read_u32().await? {
                    paths.push(PathBuf::from(String::from_utf8(
                        read_string(stream).await?,
                    )?));
                }
                RequestType::Mkdir { parent, paths }
            }
            5 => RequestType::Ps,
            6 => {
                let pid = stream.read_u64().await?;
                let signal = stream.read_i32().await?;
                RequestType::Kill { pid, signal }
            }
            7 => {
                let recursive = stream.read_u8().await? == 1;

                let mut paths = vec![];
                for _ in 0..stream.read_u32().await? {
                    paths.push(PathBuf::from(String::from_utf8(
                        read_string(stream).await?,
                    )?));
                }
                RequestType::Rm { recursive, paths }
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
            RequestType::Download { max, path } => {
                stream.write_u64(*max).await?;
                write_string(stream, path.to_str().ok_or(err)?.as_bytes()).await?;
            }
            RequestType::Mkdir { parent, paths } => {
                stream.write_u8(u8::from(*parent)).await?;

                stream.write_u32(paths.len() as u32).await?;
                for path in paths {
                    write_string(stream, path.to_str().ok_or(err.clone())?.as_bytes()).await?;
                }
            }
            RequestType::Kill { pid, signal } => {
                stream.write_u64(*pid).await?;
                stream.write_i32(*signal).await?;
            }
            RequestType::Rm { recursive, paths } => {
                stream.write_u8(u8::from(*recursive)).await?;

                stream.write_u32(paths.len() as u32).await?;
                for path in paths {
                    write_string(stream, path.to_str().ok_or(err.clone())?.as_bytes()).await?;
                }
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

    pub fn into_rtype(self) -> RequestType {
        self._rtype
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_request_pwd_serialization() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let request = Request::new(123, src, dest, RequestType::Pwd);

        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            request.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let deserialized = Request::from_stream(&mut reader).await.unwrap();

        assert_eq!(deserialized.request_id(), 123);
        assert_eq!(deserialized.src(), src);
        assert_eq!(deserialized.dest(), dest);
        matches!(deserialized.rtype(), RequestType::Pwd);
    }

    #[tokio::test]
    async fn test_request_ls_serialization() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let path = PathBuf::from("/home/user");
        let request = Request::new(456, src, dest, RequestType::Ls { path: path.clone() });

        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            request.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let deserialized = Request::from_stream(&mut reader).await.unwrap();

        assert_eq!(deserialized.request_id(), 456);
        if let RequestType::Ls { path: deser_path } = deserialized.rtype() {
            assert_eq!(deser_path, &path);
        } else {
            panic!("Expected RequestType::Ls");
        }
    }

    #[tokio::test]
    async fn test_request_download_serialization() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let path = PathBuf::from("/tmp/file.txt");
        let max_size = 1024;
        let request = Request::new(
            789,
            src,
            dest,
            RequestType::Download {
                max: max_size,
                path: path.clone(),
            },
        );

        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            request.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let deserialized = Request::from_stream(&mut reader).await.unwrap();

        if let RequestType::Download {
            max,
            path: deser_path,
        } = deserialized.rtype()
        {
            assert_eq!(*max, max_size);
            assert_eq!(deser_path, &path);
        } else {
            panic!("Expected RequestType::Download");
        }
    }

    #[tokio::test]
    async fn test_request_mkdir_serialization() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let paths = vec![
            PathBuf::from("/tmp/dir1"),
            PathBuf::from("/tmp/dir2"),
            PathBuf::from("/tmp/dir3"),
        ];
        let request = Request::new(
            101,
            src,
            dest,
            RequestType::Mkdir {
                parent: true,
                paths: paths.clone(),
            },
        );

        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            request.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let deserialized = Request::from_stream(&mut reader).await.unwrap();

        if let RequestType::Mkdir {
            parent,
            paths: deser_paths,
        } = deserialized.rtype()
        {
            assert_eq!(*parent, true);
            assert_eq!(deser_paths, &paths);
        } else {
            panic!("Expected RequestType::Mkdir");
        }
    }

    #[tokio::test]
    async fn test_request_kill_serialization() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let pid = 12345;
        let signal = 9;
        let request = Request::new(202, src, dest, RequestType::Kill { pid, signal });

        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            request.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let deserialized = Request::from_stream(&mut reader).await.unwrap();

        if let RequestType::Kill {
            pid: deser_pid,
            signal: deser_signal,
        } = deserialized.rtype()
        {
            assert_eq!(*deser_pid, pid);
            assert_eq!(*deser_signal, signal);
        } else {
            panic!("Expected RequestType::Kill");
        }
    }

    #[tokio::test]
    async fn test_request_rm_serialization() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let paths = vec![
            PathBuf::from("/tmp/file1.txt"),
            PathBuf::from("/tmp/file2.txt"),
        ];
        let request = Request::new(
            303,
            src,
            dest,
            RequestType::Rm {
                recursive: false,
                paths: paths.clone(),
            },
        );

        let mut buffer = vec![];
        {
            let mut writer = BufWriter::new(&mut buffer);
            request.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(buffer.as_slice());
        let deserialized = Request::from_stream(&mut reader).await.unwrap();

        if let RequestType::Rm {
            recursive,
            paths: deser_paths,
        } = deserialized.rtype()
        {
            assert_eq!(*recursive, false);
            assert_eq!(deser_paths, &paths);
        } else {
            panic!("Expected RequestType::Rm");
        }
    }

    #[tokio::test]
    async fn test_request_type_opcodes() {
        assert_eq!(RequestType::Pwd.opcode(), 0);
        assert_eq!(
            RequestType::Ls {
                path: PathBuf::new()
            }
            .opcode(),
            1
        );
        assert_eq!(
            RequestType::Cd {
                path: PathBuf::new()
            }
            .opcode(),
            2
        );
        assert_eq!(
            RequestType::Download {
                max: 0,
                path: PathBuf::new()
            }
            .opcode(),
            3
        );
        assert_eq!(
            RequestType::Mkdir {
                parent: false,
                paths: vec![]
            }
            .opcode(),
            4
        );
        assert_eq!(RequestType::Ps.opcode(), 5);
        assert_eq!(RequestType::Kill { pid: 0, signal: 0 }.opcode(), 6);
        assert_eq!(
            RequestType::Rm {
                recursive: false,
                paths: vec![]
            }
            .opcode(),
            7
        );
    }

    #[tokio::test]
    async fn test_invalid_opcode_error() {
        let buffer = vec![255u8]; // Invalid opcode
        let mut reader = BufReader::new(buffer.as_slice());

        let result = Request::from_stream(&mut reader).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_request_getters() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let request = Request::new(999, src, dest, RequestType::Ps);

        assert_eq!(request.request_id(), 999);
        assert_eq!(request.src(), src);
        assert_eq!(request.dest(), dest);
        matches!(request.rtype(), RequestType::Ps);

        let rtype = request.into_rtype();
        matches!(rtype, RequestType::Ps);
    }
}
