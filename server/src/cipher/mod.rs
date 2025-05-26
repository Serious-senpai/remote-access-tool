pub mod chacha20poly1305;
pub mod none;

use std::error::Error;

use rsa::sha2::Digest;
use rsa::BigUint;
use tokio::io::AsyncReadExt;

use super::errors::RuntimeError;
use super::utils::write_biguint;
use super::Packet;

pub struct CipherCtx<'a> {
    pub seq: u32,
    pub iv: &'a [u8],
    pub enc_key: &'a [u8],
    pub int_key: &'a [u8],
}

impl CipherCtx<'_> {
    pub const DUMMY: CipherCtx<'static> = CipherCtx {
        seq: 0,
        iv: &[],
        enc_key: &[],
        int_key: &[],
    };
}

pub trait Cipher {
    async fn extract_raw_packet<S>(stream: &mut S) -> Result<Packet<Self>, Box<dyn Error>>
    where
        S: AsyncReadExt + Unpin,
        Self: Sized,
    {
        let packet_length = stream.read_u32().await?;
        let padding_length = stream.read_u8().await?;

        let mut payload = vec![0u8; packet_length as usize - padding_length as usize - 1];
        stream.read_exact(&mut payload).await?;

        let mut random_padding = vec![0u8; padding_length as usize];
        stream.read_exact(&mut random_padding).await?;

        Ok(Packet::<Self>::new(
            packet_length,
            padding_length,
            payload.to_vec(),
            random_padding.to_vec(),
        ))
    }

    async fn expand_key<H, const L: usize>(
        shared_secret: &[u8],
        exchange_hash: &[u8],
        session_id: &[u8],
        letter: u8,
    ) -> Result<[u8; L], Box<dyn Error>>
    where
        H: Digest,
    {
        let mut buffer = vec![];
        write_biguint(&mut buffer, &BigUint::from_bytes_be(&shared_secret)).await?;
        buffer.extend_from_slice(&exchange_hash);
        buffer.push(letter);
        buffer.extend_from_slice(&session_id);

        let mut last = H::digest(buffer);

        let mut result = vec![];
        result.extend_from_slice(&last);

        while result.len() < L {
            let mut buffer = vec![];
            write_biguint(&mut buffer, &BigUint::from_bytes_be(&shared_secret)).await?;
            buffer.extend_from_slice(&exchange_hash);
            buffer.extend_from_slice(&last);

            last = H::digest(buffer);
            result.extend_from_slice(&last);
        }

        result.truncate(L);
        Ok(result
            .try_into()
            .map_err(|_| RuntimeError::new("Key expansion error"))?)
    }

    fn create_padding(payload_size: usize) -> Vec<u8>;
    async fn encrypt(
        ctx: &CipherCtx<'_>,
        packet_length: u32,
        padding_length: u8,
        payload: &[u8],
        random_padding: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>;

    async fn decrypt<S>(
        ctx: &CipherCtx<'_>,
        stream: &mut S,
    ) -> Result<Packet<Self>, Box<dyn Error>>
    where
        S: AsyncReadExt + Unpin,
        Self: Sized;
}
