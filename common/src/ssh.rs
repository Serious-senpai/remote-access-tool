use std::error::Error;
use std::mem::swap;

use log::{debug, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout, Duration};

use super::cipher::encryption::{Cipher, CipherCtx};
use super::cipher::kex::KexAlgorithm;
use super::packets::Packet;
use super::payloads::PayloadFormat;

/// Thread-safe SSH connection controller.
///
/// It is guarateed that both reading and writing requests will not suffer from starvation.
pub struct SSH<C>
where
    C: Cipher,
{
    _stream: Mutex<TcpStream>,
    _send_ctx: Mutex<CipherCtx<C>>,
    _receive_ctx: Mutex<CipherCtx<C>>,
}

impl<C> SSH<C>
where
    C: Cipher,
{
    /// Construct a new SSH connection controller.
    pub fn new(stream: TcpStream, send_ctx: CipherCtx<C>, receive_ctx: CipherCtx<C>) -> Self {
        Self {
            _stream: Mutex::new(stream),
            _send_ctx: Mutex::new(send_ctx),
            _receive_ctx: Mutex::new(receive_ctx),
        }
    }

    /// Read the version string from peer
    pub async fn read_version_string(
        &mut self,
        verbose: bool,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let mut buf = vec![];
        let mut stream = self._stream.lock().await;
        loop {
            let byte = stream.read_u8().await?;
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
        &mut self,
        version: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut stream = self._stream.lock().await;
        stream.write_all(version.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        stream.flush().await?;
        debug!("Sent version string: {}", version);
        Ok(())
    }

    /// Peek the next byte in the stream.
    pub async fn peek(&self) -> u8 {
        let mut buf = [0; 1];
        let stream = self._stream.lock().await;

        // Peek the first byte to check if a packet is available
        let _ = stream.peek(&mut buf).await;
        buf[0]
    }

    /// Read a packet from the stream.
    ///
    /// WARNING: This is not cancel-safe - canceling the future will leave us in a random position
    /// in the stream. It is recommended to [peek] first to wait until a packet is available
    pub async fn read_packet(&mut self) -> Result<Packet<C>, Box<dyn Error + Send + Sync>> {
        // Release the lock every 500 milliseconds to allow other scheduling tasks to run
        // (tokio mutex guarantees FIFO order).
        let mut receive_ctx = self._receive_ctx.lock().await;
        debug!("Waiting for incoming packet (seq={})...", receive_ctx.seq);

        let mut buf = [0; 1];
        loop {
            {
                let mut stream = self._stream.lock().await;

                if timeout(Duration::from_millis(500), stream.peek(&mut buf))
                    .await
                    .is_ok()
                {
                    let packet = Packet::<C>::from_stream(&receive_ctx, &mut *stream).await?;
                    debug!("Received new packet (seq={})", receive_ctx.seq);
                    receive_ctx.seq += 1;

                    break Ok(packet);
                }
            }

            sleep(Duration::from_millis(500)).await;
        }
    }

    pub async fn write_packet(
        &mut self,
        packet: &Packet<C>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut send_ctx = self._send_ctx.lock().await;
        let mut stream = self._stream.lock().await;

        debug!("Sending packet (seq={})", send_ctx.seq);
        packet.to_stream(&send_ctx, &mut *stream).await?;
        send_ctx.seq += 1;

        Ok(())
    }

    pub async fn write_payload<P>(
        &mut self,
        payload: &P,
    ) -> Result<Packet<C>, Box<dyn Error + Send + Sync>>
    where
        P: PayloadFormat + Sync,
    {
        let mut send_ctx = self._send_ctx.lock().await;
        let mut stream = self._stream.lock().await;

        debug!("Sending packet (seq={})", send_ctx.seq);
        let packet = payload.to_packet(&send_ctx).await?;
        packet.to_stream(&send_ctx, &mut *stream).await?;
        send_ctx.seq += 1;

        Ok(packet)
    }

    pub async fn write_raw_payload(
        &mut self,
        payload: Vec<u8>,
    ) -> Result<Packet<C>, Box<dyn Error + Send + Sync>> {
        let mut send_ctx = self._send_ctx.lock().await;
        let mut stream = self._stream.lock().await;

        debug!("Sending packet (seq={})", send_ctx.seq);
        let packet = Packet::<C>::from_payload(&send_ctx, payload).await?;
        packet.to_stream(&send_ctx, &mut *stream).await?;
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
            _stream: self._stream,
            _send_ctx: Mutex::new(send_ctx),
            _receive_ctx: Mutex::new(receive_ctx),
        })
    }
}
