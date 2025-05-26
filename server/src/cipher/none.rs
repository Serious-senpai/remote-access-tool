use std::error::Error;

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::packets::{Packet, MIN_PACKET_LENGTH, MIN_PADDING_LENGTH};
use super::{Cipher, CipherCtx};

#[derive(Debug, Clone)]
pub struct NoneCipher {}

impl Cipher for NoneCipher {
    fn create_padding(payload_size: usize) -> Vec<u8> {
        let block_size = 8;
        let current_size = 5 + payload_size;
        let mut padding_len = if current_size <= MIN_PACKET_LENGTH {
            MIN_PACKET_LENGTH - current_size
        } else {
            block_size - current_size % block_size
        };

        if padding_len < MIN_PADDING_LENGTH {
            padding_len += block_size
        }

        let mut padding = vec![0u8; padding_len];
        let mut rng = StdRng::from_os_rng();
        rng.fill_bytes(&mut padding);
        padding
    }

    async fn encrypt(
        _ctx: &CipherCtx<'_>,
        packet_length: u32,
        padding_length: u8,
        payload: &[u8],
        random_padding: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        let mut buffer = vec![];
        buffer.write_u32(packet_length).await?;
        buffer.write_u8(padding_length).await?;
        buffer.write_all(payload).await?;
        buffer.write_all(random_padding).await?;
        buffer.flush().await?;
        Ok((buffer, vec![]))
    }

    async fn decrypt<S>(
        _ctx: &CipherCtx<'_>,
        stream: &mut S,
    ) -> Result<Packet<Self>, Box<dyn Error>>
    where
        S: AsyncReadExt + Unpin,
        Self: Sized,
    {
        Self::extract_raw_packet(stream).await
    }
}
