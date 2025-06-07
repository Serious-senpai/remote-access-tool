use std::error::Error;
use std::marker::PhantomData;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::cipher::encryption::{Cipher, CipherCtx};

pub const MIN_PACKET_LENGTH: usize = 16;
pub const MIN_PADDING_LENGTH: usize = 4;

#[derive(Debug, Clone)]
pub struct Packet<C>
where
    C: Cipher,
{
    pub packet_length: u32,
    pub padding_length: u8,
    pub payload: Vec<u8>,
    pub random_padding: Vec<u8>,
    phantom: PhantomData<C>,
}

impl<C> Packet<C>
where
    C: Cipher,
{
    pub fn new(
        packet_length: u32,
        padding_length: u8,
        payload: Vec<u8>,
        random_padding: Vec<u8>,
    ) -> Self {
        Self {
            packet_length,
            padding_length,
            payload,
            random_padding,
            phantom: PhantomData,
        }
    }

    /// Generate a new SSH packet from a payload
    pub async fn from_payload(
        _ctx: &CipherCtx<C>,
        payload: Vec<u8>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let random_padding = C::create_padding(payload.len());
        let packet_length = (1 + payload.len() + random_padding.len()) as u32;

        Ok(Self::new(
            packet_length,
            random_padding.len() as u8,
            payload,
            random_padding,
        ))
    }

    /// Read an SSH packet from a stream.
    pub async fn from_stream<S>(
        ctx: &CipherCtx<C>,
        stream: &mut S,
    ) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
    {
        C::decrypt(ctx, stream).await
    }

    /// Write the entire SSH packet to a stream.
    pub async fn to_stream<S>(
        &self,
        ctx: &CipherCtx<C>,
        stream: &mut S,
    ) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Unpin,
    {
        let (encrypted, mac) = C::encrypt(
            ctx,
            self.packet_length,
            self.padding_length,
            &self.payload,
            &self.random_padding,
        )
        .await?;
        stream.write_all(&encrypted).await?;
        stream.write_all(&mac).await?;
        stream.flush().await?;
        Ok(())
    }

    pub fn peek_opcode(&self) -> Option<u8> {
        self.payload.first().cloned()
    }
}
