use std::error::Error;
use std::mem::swap;

use log::{debug, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use super::cipher::encryption::{Cipher, CipherCtx};
use super::cipher::kex::KexAlgorithm;
use super::packets::Packet;
use super::payloads::PayloadFormat;

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
    C: Cipher + Sync,
{
    pub fn new(stream: TcpStream, send_ctx: CipherCtx<C>, receive_ctx: CipherCtx<C>) -> Self {
        Self {
            _stream: Mutex::new(stream),
            _send_ctx: Mutex::new(send_ctx),
            _receive_ctx: Mutex::new(receive_ctx),
        }
    }

    pub async fn read_version_string(&mut self, verbose: bool) -> Result<String, Box<dyn Error>> {
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
                    return Ok::<String, Box<dyn Error>>(trimmed.into());
                }

                buf = vec![];
            }
        }
    }

    pub async fn write_version_string(&mut self, version: &str) -> Result<(), Box<dyn Error>> {
        let mut stream = self._stream.lock().await;
        stream.write_all(version.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        stream.flush().await?;
        debug!("Sent version string: {}", version);
        Ok(())
    }

    pub async fn read_packet(&mut self) -> Result<Packet<C>, Box<dyn Error>> {
        let mut stream = self._stream.lock().await;
        let mut receive_ctx = self._receive_ctx.lock().await;

        let packet = Packet::<C>::from_stream(&receive_ctx, &mut *stream).await?;
        receive_ctx.seq += 1;

        Ok(packet)
    }

    pub async fn write_packet(&mut self, packet: &Packet<C>) -> Result<(), Box<dyn Error>> {
        let mut stream = self._stream.lock().await;
        let mut send_ctx = self._send_ctx.lock().await;

        packet.to_stream(&send_ctx, &mut *stream).await?;
        send_ctx.seq += 1;

        Ok(())
    }

    pub async fn write_payload<P>(&mut self, payload: &P) -> Result<Packet<C>, Box<dyn Error>>
    where
        P: PayloadFormat + Sync,
    {
        let mut stream = self._stream.lock().await;
        let mut send_ctx = self._send_ctx.lock().await;

        let packet = payload.to_packet(&send_ctx).await?;
        packet.to_stream(&send_ctx, &mut *stream).await?;
        send_ctx.seq += 1;

        Ok(packet)
    }

    pub async fn switch_encryption<K, C2, const SERVER: bool>(
        self,
        shared_secret: &[u8],
        exchange_hash: &[u8],
        session_id: &[u8],
    ) -> Result<SSH<C2>, Box<dyn Error>>
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
