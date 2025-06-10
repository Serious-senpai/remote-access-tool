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
