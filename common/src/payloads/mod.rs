pub mod custom;
pub mod disconnect;
pub mod ignore;
pub mod kex_ecdh_init;
pub mod kex_ecdh_reply;
pub mod kexinit;
pub mod newkeys;

use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, BufReader};

use super::cipher::encryption::{Cipher, CipherCtx};
use super::errors::UnexpectedPacket;
use super::packets::Packet;

#[async_trait]
pub trait PayloadFormat {
    const OPCODE: u8;

    /// Construct this payload from a stream. The stream must start from the opcode.
    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized;

    /// Construct this payload from a byte slice. The slice must start from the opcode.
    async fn from_payload(payload: &[u8]) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let mut reader = BufReader::new(payload);
        Self::from_stream(&mut reader).await
    }

    /// Extract the payload field from [Packet].
    async fn from_packet<C>(packet: &Packet<C>) -> Result<Self, Box<dyn Error>>
    where
        C: Cipher + Sync,
        Self: Sized,
    {
        Self::from_payload(&packet.payload).await
    }

    fn _check_opcode(opcode: u8) -> Result<(), UnexpectedPacket> {
        if opcode != Self::OPCODE {
            Err(UnexpectedPacket::new(Self::OPCODE, opcode))
        } else {
            Ok(())
        }
    }

    /// Write this payload to a stream. The data will start from the opcode.
    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: tokio::io::AsyncWriteExt + Send + Unpin,
        Self: Sized;

    /// Create a vector consisting of the payload bytes, starting from the opcode.
    async fn to_payload(&self) -> Result<Vec<u8>, Box<dyn Error>>
    where
        Self: Sized,
    {
        let mut writer = vec![];
        self.to_stream(&mut writer).await?;
        Ok(writer)
    }

    /// Create a [Packet] with this payload.
    async fn to_packet<C>(&self, ctx: &CipherCtx<C>) -> Result<Packet<C>, Box<dyn Error>>
    where
        C: Cipher + Sync,
        Self: Sized,
    {
        let payload = self.to_payload().await?;
        Packet::<C>::from_payload(ctx, payload).await
    }
}
