use std::error::Error;

use async_trait::async_trait;
use rand::seq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::super::utils::{read_string, write_string};
use super::super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct Command {
    _request_id: u32,
    _seq: u32,
    _stdout: Vec<u8>,
    _stderr: Vec<u8>,
    _completed: bool,
    _exit_code: u32,
}

#[async_trait]
impl PayloadFormat for Command {
    const OPCODE: u8 = 192;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let request_id = stream.read_u32().await?;
        let seq = stream.read_u32().await?;
        let stdout = read_string(stream).await?;
        let stderr = read_string(stream).await?;
        let completed = stream.read_u8().await? != 0;
        let exit_code = stream.read_u32().await?;

        Ok(Self {
            _request_id: request_id,
            _seq: seq,
            _stdout: stdout,
            _stderr: stderr,
            _completed: completed,
            _exit_code: exit_code,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_u32(self._request_id).await?;
        stream.write_u32(self._seq).await?;
        write_string(stream, &self._stdout).await?;
        write_string(stream, &self._stderr).await?;
        stream.write_u8(if self._completed { 1 } else { 0 }).await?;
        stream.write_u32(self._exit_code).await?;
        Ok(())
    }
}

impl Command {
    pub fn new(
        request_id: u32,
        seq: u32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        completed: bool,
        exit_code: u32,
    ) -> Self {
        Self {
            _request_id: request_id,
            _seq: seq,
            _stdout: stdout,
            _stderr: stderr,
            _completed: completed,
            _exit_code: exit_code,
        }
    }

    /// The request ID for the execution.
    pub fn request_id(&self) -> u32 {
        self._request_id
    }

    /// Sequence number of this packet. When stdout or stderr is too long, the client will fragment the data
    /// and send them in multiple packets.
    pub fn seq(&self) -> u32 {
        self._seq
    }

    /// The standard output of the command.
    pub fn stdout(&self) -> &[u8] {
        &self._stdout
    }

    /// The standard error of the command.
    pub fn stderr(&self) -> &[u8] {
        &self._stderr
    }

    /// Whether the command was completed.
    pub fn completed(&self) -> bool {
        self._completed
    }

    /// The exit code of the command (will be 0 if the command hasn't been completed yet).
    pub fn exit_code(&self) -> u32 {
        self._exit_code
    }
}
