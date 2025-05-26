use std::error::Error;

use chacha20::cipher::{
    BlockSizeUser, KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek, Unsigned,
};
use chacha20::{ChaCha20Legacy, ChaCha20LegacyCore};
use poly1305::Poly1305;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

use super::super::errors::RuntimeError;
use super::super::packets::{Packet, MIN_PACKET_LENGTH, MIN_PADDING_LENGTH};
use super::{Cipher, CipherCtx};

#[derive(Debug, Clone)]
pub struct ChaCha20Poly1305 {}

impl Cipher for ChaCha20Poly1305 {
    fn create_padding(payload_size: usize) -> Vec<u8> {
        let block_size = 8;
        let current_size = 1 + payload_size;
        let mut padding_len = if current_size <= MIN_PACKET_LENGTH {
            MIN_PACKET_LENGTH - current_size
        } else {
            block_size - current_size % block_size
        };

        if padding_len < MIN_PADDING_LENGTH {
            padding_len += block_size
        }

        vec![0u8; padding_len]
    }

    async fn encrypt(
        ctx: &CipherCtx<'_>,
        packet_length: u32,
        padding_length: u8,
        payload: &[u8],
        random_padding: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        let k_length = ctx.enc_key[32..].to_vec();
        let k_payload = ctx.enc_key[..32].to_vec();

        let mut nonce = vec![0u8; 4];
        nonce.write_u32(ctx.seq).await?;

        let mut buffer = vec![];
        buffer.write_u32(packet_length).await?;
        buffer.write_u8(padding_length).await?;
        buffer.write_all(payload).await?;
        buffer.write_all(random_padding).await?;

        // ChaCha20 encryption
        let mut cipher =
            <ChaCha20Legacy as KeyIvInit>::new(k_length.as_slice().into(), nonce.as_slice().into());
        cipher.apply_keystream(&mut buffer[..4]);

        let mut cipher = <ChaCha20Legacy as KeyIvInit>::new(
            k_payload.as_slice().into(),
            nonce.as_slice().into(),
        );
        cipher.seek(<ChaCha20LegacyCore as BlockSizeUser>::BlockSize::to_usize()); // skip to block counter = 1
        cipher.apply_keystream(&mut buffer[4..]);

        // Poly1305 authentication
        let mut cipher = <ChaCha20Legacy as KeyIvInit>::new(
            k_payload.as_slice().into(),
            nonce.as_slice().into(),
        );
        let mut poly_key = vec![0u8; 32];
        cipher.apply_keystream(poly_key.as_mut_slice());

        let tag = Poly1305::new(poly_key.as_slice().into()).compute_unpadded(&buffer);

        Ok((buffer, tag.to_vec()))
    }

    async fn decrypt<S>(ctx: &CipherCtx<'_>, stream: &mut S) -> Result<Packet<Self>, Box<dyn Error>>
    where
        S: AsyncReadExt + Unpin,
        Self: Sized,
    {
        let k_length = ctx.enc_key[32..].to_vec();
        let k_payload = ctx.enc_key[..32].to_vec();

        let mut nonce = vec![0u8; 4];
        nonce.write_u32(ctx.seq).await?;

        let mut encrypted = vec![0u8; 4];
        stream.read_exact(&mut encrypted).await?;

        let mut packet_length_buf = [0u8; 4];

        // Decode packet length
        let mut cipher =
            <ChaCha20Legacy as KeyIvInit>::new(k_length.as_slice().into(), nonce.as_slice().into());
        cipher
            .apply_keystream_b2b(&encrypted, &mut packet_length_buf)
            .map_err(|_| RuntimeError::new("Packet decryption error"))?;

        let packet_length = u32::from_be_bytes(packet_length_buf);

        if packet_length < MIN_PACKET_LENGTH as u32 {
            Err(RuntimeError::new(format!(
                "Invalid packet length {}",
                packet_length
            )))?;
        }

        encrypted.resize(4 + packet_length as usize, 0);
        stream.read_exact(&mut encrypted[4..]).await?;

        // Authenticate data
        let mut cipher = <ChaCha20Legacy as KeyIvInit>::new(
            k_payload.as_slice().into(),
            nonce.as_slice().into(),
        );
        let mut poly_key = vec![0u8; 32];
        cipher.apply_keystream(poly_key.as_mut_slice());

        let expected_tag = Poly1305::new(poly_key.as_slice().into()).compute_unpadded(&encrypted);

        let mut actual_tag = vec![0u8; 16];
        stream.read_exact(&mut actual_tag).await?;

        if expected_tag.as_slice() != actual_tag.as_slice() {
            Err(RuntimeError::new("Invalid MAC for ChaCha20Poly1305 packet"))?;
        }

        // Decrypt buffer
        let mut cipher = <ChaCha20Legacy as KeyIvInit>::new(
            k_payload.as_slice().into(),
            nonce.as_slice().into(),
        );
        cipher.seek(<ChaCha20LegacyCore as BlockSizeUser>::BlockSize::to_usize()); // skip to block counter = 1
        cipher.apply_keystream(&mut encrypted[4..]);
        encrypted[..4].copy_from_slice(&packet_length_buf);

        let mut reader = BufReader::new(encrypted.as_slice());
        Self::extract_raw_packet(&mut reader).await
    }
}
