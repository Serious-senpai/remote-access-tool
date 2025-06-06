pub mod chacha20_poly1305;
pub mod none;

use async_trait::async_trait;
use rsa::BigUint;
use ssh_key::sha2::Digest;
use std::error::Error;
use std::marker::PhantomData;
use tokio::io::AsyncReadExt;

use super::super::errors::RuntimeError;
use super::super::packets::Packet;
use super::super::utils::write_biguint_vec;
use super::kex::KexAlgorithm;

pub struct CipherCtx<C>
where
    C: Cipher,
{
    pub seq: u32,
    pub iv: Vec<u8>,
    pub enc_key: Vec<u8>,
    pub int_key: Vec<u8>,
    _cipher: PhantomData<C>,
}

impl CipherCtx<none::NoneCipher> {
    pub const DUMMY: Self = Self {
        seq: 0,
        iv: vec![],
        enc_key: vec![],
        int_key: vec![],
        _cipher: PhantomData,
    };
}

impl<C> CipherCtx<C>
where
    C: Cipher,
{
    pub async fn new<K>(
        seq: u32,
        iv_letter: u8,
        enc_key_letter: u8,
        int_key_letter: u8,
        shared_secret: &[u8],
        exchange_hash: &[u8],
        session_id: &[u8],
    ) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        K: KexAlgorithm,
    {
        async fn construct_base<K>(
            letter: u8,
            required_length: usize,
            shared_secret: &[u8],
            exchange_hash: &[u8],
            session_id: &[u8],
        ) -> Vec<u8>
        where
            K: KexAlgorithm,
        {
            if required_length == 0 {
                return vec![];
            }

            let mut buffer = vec![];
            write_biguint_vec(&mut buffer, &BigUint::from_bytes_be(shared_secret)).await;
            buffer.extend_from_slice(exchange_hash);
            buffer.push(letter);
            buffer.extend_from_slice(session_id);

            let mut last = K::hash(&buffer);

            let mut result = vec![];
            result.extend_from_slice(&last);

            while result.len() < required_length {
                let mut buffer = vec![];
                write_biguint_vec(&mut buffer, &BigUint::from_bytes_be(shared_secret)).await;
                buffer.extend_from_slice(exchange_hash);
                buffer.extend_from_slice(&last);

                last = K::hash(&buffer);
                result.extend_from_slice(&last);
            }

            result.truncate(required_length);
            result
        }

        let iv = construct_base::<K>(
            iv_letter,
            C::IV_SIZE,
            shared_secret,
            exchange_hash,
            session_id,
        )
        .await;
        let enc_key = construct_base::<K>(
            enc_key_letter,
            C::ENC_SIZE,
            shared_secret,
            exchange_hash,
            session_id,
        )
        .await;
        let int_key = construct_base::<K>(
            int_key_letter,
            C::INT_SIZE,
            shared_secret,
            exchange_hash,
            session_id,
        )
        .await;

        Ok(Self {
            seq,
            iv,
            enc_key,
            int_key,
            _cipher: PhantomData,
        })
    }
}

#[async_trait]
pub trait Cipher: Clone + Send + Sync {
    const NAME: &str;
    const IV_SIZE: usize;
    const ENC_SIZE: usize;
    const INT_SIZE: usize;

    async fn extract_raw_packet<S>(
        stream: &mut S,
    ) -> Result<Packet<Self>, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
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
    ) -> Result<[u8; L], Box<dyn Error + Send + Sync>>
    where
        H: Digest,
    {
        let mut buffer = vec![];
        write_biguint_vec(&mut buffer, &BigUint::from_bytes_be(shared_secret)).await;
        buffer.extend_from_slice(exchange_hash);
        buffer.push(letter);
        buffer.extend_from_slice(session_id);

        let mut last = H::digest(buffer);

        let mut result = vec![];
        result.extend_from_slice(&last);

        while result.len() < L {
            let mut buffer = vec![];
            write_biguint_vec(&mut buffer, &BigUint::from_bytes_be(shared_secret)).await;
            buffer.extend_from_slice(exchange_hash);
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
        ctx: &CipherCtx<Self>,
        packet_length: u32,
        padding_length: u8,
        payload: &[u8],
        random_padding: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error + Send + Sync>>
    where
        Self: Sized;

    async fn decrypt<S>(
        ctx: &CipherCtx<Self>,
        stream: &mut S,
    ) -> Result<Packet<Self>, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized;
}
