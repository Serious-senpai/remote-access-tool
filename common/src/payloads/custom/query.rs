use std::error::Error;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::errors::RuntimeError;
use crate::payloads::PayloadFormat;
use crate::utils::{read_address, read_string, write_address, write_string};

#[derive(Debug, Clone)]
pub enum QueryType {
    Authenticate { rkey: Vec<u8> },
    ClientLs,
    ClientDisconnect { addr: SocketAddr },
}

impl QueryType {
    fn opcode(&self) -> u8 {
        match self {
            Self::Authenticate { .. } => 0,
            Self::ClientLs => 1,
            Self::ClientDisconnect { .. } => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Query {
    _request_id: u32,
    _qtype: QueryType,
}

#[async_trait]
impl PayloadFormat for Query {
    const OPCODE: u8 = 195;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let request_id = stream.read_u32().await?;
        let qtype = match stream.read_u8().await? {
            0 => {
                let rkey = read_string(stream).await?;
                QueryType::Authenticate { rkey }
            }
            1 => QueryType::ClientLs,
            2 => {
                let addr = read_address(stream).await?;
                QueryType::ClientDisconnect { addr }
            }
            opcode => Err(RuntimeError::new(format!(
                "Unknown query opcode {}",
                opcode
            )))?,
        };

        Ok(Self {
            _request_id: request_id,
            _qtype: qtype,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_u32(self._request_id).await?;

        stream.write_u8(self._qtype.opcode()).await?;

        match &self._qtype {
            QueryType::Authenticate { rkey } => {
                write_string(stream, rkey).await?;
            }
            QueryType::ClientLs => (),
            QueryType::ClientDisconnect { addr } => {
                write_address(stream, addr).await?;
            }
        }

        Ok(())
    }
}

impl Query {
    pub fn new(request_id: u32, qtype: QueryType) -> Self {
        Self {
            _request_id: request_id,
            _qtype: qtype,
        }
    }

    pub fn request_id(&self) -> u32 {
        self._request_id
    }

    pub fn qtype(&self) -> &QueryType {
        &self._qtype
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_authenticate_query_roundtrip() {
        let rkey = b"test_key".to_vec();
        let query = Query::new(42, QueryType::Authenticate { rkey: rkey.clone() });

        // Write to Vec
        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            query.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Read from Vec
        let mut reader = BufReader::new(buffer.as_slice());
        let parsed_query = Query::from_stream(&mut reader).await.unwrap();

        assert_eq!(parsed_query.request_id(), 42);
        match parsed_query.qtype() {
            QueryType::Authenticate { rkey: parsed_rkey } => {
                assert_eq!(parsed_rkey, &rkey);
            }
            _ => panic!("Expected Authenticate query type"),
        }
    }

    #[tokio::test]
    async fn test_client_ls_query_roundtrip() {
        let query = Query::new(123, QueryType::ClientLs);

        // Write to Vec
        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            query.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Read from Vec
        let mut reader = BufReader::new(buffer.as_slice());
        let parsed_query = Query::from_stream(&mut reader).await.unwrap();

        assert_eq!(parsed_query.request_id(), 123);
        match parsed_query.qtype() {
            QueryType::ClientLs => {}
            _ => panic!("Expected ClientLs query type"),
        }
    }

    #[tokio::test]
    async fn test_client_disconnect_query_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let query = Query::new(456, QueryType::ClientDisconnect { addr });

        // Write to Vec
        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            query.to_stream(&mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Read from Vec
        let mut reader = BufReader::new(buffer.as_slice());
        let parsed_query = Query::from_stream(&mut reader).await.unwrap();

        assert_eq!(parsed_query.request_id(), 456);
        match parsed_query.qtype() {
            QueryType::ClientDisconnect { addr: parsed_addr } => {
                assert_eq!(parsed_addr, &addr);
            }
            _ => panic!("Expected ClientDisconnect query type"),
        }
    }

    #[tokio::test]
    async fn test_invalid_opcode() {
        let mut buffer = vec![99]; // Invalid opcode
        buffer.extend_from_slice(&42u32.to_be_bytes()); // request_id
        buffer.push(0); // query type
        buffer.extend_from_slice(&4u32.to_be_bytes()); // string length
        buffer.extend_from_slice(b"test"); // string data

        let mut reader = BufReader::new(buffer.as_slice());
        let result = Query::from_stream(&mut reader).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_query_type() {
        let mut buffer = vec![Query::OPCODE];
        buffer.extend_from_slice(&42u32.to_be_bytes()); // request_id
        buffer.push(99); // Invalid query type

        let mut reader = BufReader::new(buffer.as_slice());
        let result = Query::from_stream(&mut reader).await;

        assert!(result.is_err());
    }
}
