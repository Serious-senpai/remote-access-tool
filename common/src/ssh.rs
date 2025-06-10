use std::error::Error;
use std::io;
use std::mem::swap;
use std::net::SocketAddr;

use log::{debug, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::cipher::encryption::{Cipher, CipherCtx};
use crate::cipher::kex::KexAlgorithm;
use crate::packets::Packet;
use crate::payloads::PayloadFormat;

/// Thread-safe SSH connection controller.
///
/// It is guarateed that both reading and writing requests will not suffer from starvation.
#[derive(Debug)]
pub struct SSH<C>
where
    C: Cipher,
{
    _local_addr: SocketAddr,
    _peer_addr: SocketAddr,
    _send: Mutex<OwnedWriteHalf>,
    _send_ctx: Mutex<CipherCtx<C>>,
    _receive: Mutex<OwnedReadHalf>,
    _receive_ctx: Mutex<CipherCtx<C>>,
}

impl<C> SSH<C>
where
    C: Cipher,
{
    /// Construct a new SSH connection controller.
    pub fn new(stream: TcpStream, send_ctx: CipherCtx<C>, receive_ctx: CipherCtx<C>) -> Self {
        let local_addr = stream.local_addr().expect("Failed to get local address");
        let remote_adr = stream.peer_addr().expect("Failed to get remote address");
        let (receive, send) = stream.into_split();
        Self {
            _local_addr: local_addr,
            _peer_addr: remote_adr,
            _send: Mutex::new(send),
            _send_ctx: Mutex::new(send_ctx),
            _receive: Mutex::new(receive),
            _receive_ctx: Mutex::new(receive_ctx),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self._local_addr
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self._peer_addr
    }

    /// Read the version string from peer
    pub async fn read_version_string(
        &self,
        verbose: bool,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let mut buf = vec![];
        let mut receive = self._receive.lock().await;
        loop {
            let byte = receive.read_u8().await?;
            buf.push(byte);
            if byte == b'\n' {
                let line = String::from_utf8(buf)?;

                // Remove the CRLF (i.e. \r\n) characters
                let trimmed = line.trim_end_matches("\r\n");
                if verbose {
                    info!("{}", trimmed);
                }

                if line.starts_with("SSH-") {
                    return Ok::<String, Box<dyn Error + Send + Sync>>(trimmed.into());
                }

                buf = vec![];
            }
        }
    }

    /// Send the version string to peer
    pub async fn write_version_string(
        &self,
        version: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut send = self._send.lock().await;
        send.write_all(version.as_bytes()).await?;
        send.write_all(b"\r\n").await?;
        send.flush().await?;

        debug!("Sent version string: {}", version);
        Ok(())
    }

    /// Peek the next byte in the stream without consuming it.
    ///
    /// This method is cancel-safe.
    pub async fn peek(&self) -> io::Result<u8> {
        let mut buf = [0; 1];
        let mut receive = self._receive.lock().await;
        receive.peek(&mut buf).await?;

        Ok(buf[0])
    }

    /// Read a packet from the stream.
    ///
    /// WARNING: This is not cancel-safe - canceling the future will leave us in a random position
    /// in the stream. It is recommended to [peek] first to wait until a packet is available
    pub async fn read_packet(&self) -> Result<Packet<C>, Box<dyn Error + Send + Sync>> {
        let mut receive_ctx = self._receive_ctx.lock().await;
        debug!(
            "Waiting for incoming packet (seq={}) from {}...",
            receive_ctx.seq,
            self.peer_addr(),
        );

        let mut receive = self._receive.lock().await;
        let packet = Packet::<C>::from_stream(&receive_ctx, &mut *receive).await?;
        match packet.peek_opcode() {
            Some(opcode) => {
                debug!(
                    "Received packet (seq={}, opcode={}) from {}",
                    receive_ctx.seq, opcode, self._peer_addr
                );
            }
            None => {
                debug!(
                    "Received packet (seq={}, unknown opcode) from {}",
                    receive_ctx.seq, self._peer_addr
                );
            }
        }

        receive_ctx.seq += 1;

        Ok(packet)
    }

    fn _log_send(&self, seq: u32, opcode: Option<u8>) {
        match opcode {
            Some(op) => {
                debug!(
                    "Sending packet (seq={}, opcode={}) to {}",
                    seq, op, self._peer_addr
                );
            }
            None => {
                debug!("Sending packet (seq={}) to {}", seq, self._peer_addr);
            }
        }
    }

    pub async fn write_packet(
        &self,
        packet: &Packet<C>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut send_ctx = self._send_ctx.lock().await;
        let mut send = self._send.lock().await;

        self._log_send(send_ctx.seq, packet.peek_opcode());
        packet.to_stream(&send_ctx, &mut *send).await?;
        send_ctx.seq += 1;

        Ok(())
    }

    pub async fn write_payload<P>(
        &self,
        payload: &P,
    ) -> Result<Packet<C>, Box<dyn Error + Send + Sync>>
    where
        P: PayloadFormat + Sync,
    {
        let mut send_ctx = self._send_ctx.lock().await;
        let mut send = self._send.lock().await;

        let packet = payload.to_packet(&send_ctx).await?;
        self._log_send(send_ctx.seq, packet.peek_opcode());
        packet.to_stream(&send_ctx, &mut *send).await?;
        send_ctx.seq += 1;

        Ok(packet)
    }

    pub async fn write_raw_payload(
        &self,
        payload: Vec<u8>,
    ) -> Result<Packet<C>, Box<dyn Error + Send + Sync>> {
        let mut send_ctx = self._send_ctx.lock().await;
        let mut send = self._send.lock().await;

        let packet = Packet::<C>::from_payload(&send_ctx, payload).await?;
        self._log_send(send_ctx.seq, packet.peek_opcode());
        packet.to_stream(&send_ctx, &mut *send).await?;
        send_ctx.seq += 1;

        Ok(packet)
    }

    pub async fn switch_encryption<K, C2, const SERVER: bool>(
        self,
        shared_secret: &[u8],
        exchange_hash: &[u8],
        session_id: &[u8],
    ) -> Result<SSH<C2>, Box<dyn Error + Send + Sync>>
    where
        K: KexAlgorithm,
        C2: Cipher,
    {
        let send_ctx = self._send_ctx.lock().await;
        let receive_ctx = self._receive_ctx.lock().await;

        let mut send_ctx = CipherCtx::<C2>::new::<K>(
            send_ctx.seq,
            b'A',
            b'C',
            b'E',
            shared_secret,
            exchange_hash,
            session_id,
        )
        .await?;
        let mut receive_ctx = CipherCtx::<C2>::new::<K>(
            receive_ctx.seq,
            b'B',
            b'D',
            b'F',
            shared_secret,
            exchange_hash,
            session_id,
        )
        .await?;

        if SERVER {
            swap(&mut send_ctx, &mut receive_ctx);
        }

        Ok(SSH::<C2> {
            _local_addr: self._local_addr,
            _peer_addr: self._peer_addr,
            _send: self._send,
            _send_ctx: Mutex::new(send_ctx),
            _receive: self._receive,
            _receive_ctx: Mutex::new(receive_ctx),
        })
    }
}
