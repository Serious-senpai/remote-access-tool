use std::error::Error;

use async_trait::async_trait;
use chacha20::cipher::{
    BlockSizeUser, KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek, Unsigned,
};
use chacha20::{ChaCha20Legacy, ChaCha20LegacyCore};
use log::debug;
use poly1305::Poly1305;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

use crate::cipher::encryption::{Cipher, CipherCtx};
use crate::errors::RuntimeError;
use crate::packets::{Packet, MIN_PACKET_LENGTH, MIN_PADDING_LENGTH};

#[derive(Debug, Clone)]
pub struct ChaCha20Poly1305;

#[async_trait]
impl Cipher for ChaCha20Poly1305 {
    const NAME: &str = "chacha20-poly1305@openssh.com";
    const IV_SIZE: usize = 0;
    const ENC_SIZE: usize = 64;
    const INT_SIZE: usize = 0;

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
        ctx: &CipherCtx<Self>,
        packet_length: u32,
        padding_length: u8,
        payload: &[u8],
        random_padding: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error + Send + Sync>>
    where
        Self: Sized,
    {
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

    async fn decrypt<S>(
        ctx: &CipherCtx<Self>,
        stream: &mut S,
    ) -> Result<Packet<Self>, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
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
        debug!("Decrypted packet length {}", packet_length);

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

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_create_padding_minimum_length() {
        let padding = ChaCha20Poly1305::create_padding(10);
        assert!(padding.len() >= MIN_PADDING_LENGTH);

        // Check that packet structure meets minimum requirements
        let total_size = 4 + 1 + 10 + padding.len(); // packet_length + padding_length + payload + padding
        assert!(total_size >= MIN_PACKET_LENGTH);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let enc_key = vec![0x42u8; 64]; // 32 bytes for k_payload + 32 bytes for k_length
        let ctx = CipherCtx {
            seq: 12345,
            iv: vec![],
            enc_key,
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payload = b"Hello, ChaCha20-Poly1305!".to_vec();
        let packet = Packet::<ChaCha20Poly1305>::from_payload(&ctx, payload.clone())
            .await
            .unwrap();

        // Encrypt
        let (encrypted, mac) = ChaCha20Poly1305::encrypt(
            &ctx,
            packet.packet_length,
            packet.padding_length,
            &packet.payload,
            &packet.random_padding,
        )
        .await
        .unwrap();

        // Prepare stream for decryption
        let mut stream_data = vec![];
        stream_data.extend_from_slice(&encrypted);
        stream_data.extend_from_slice(&mac);
        let mut reader = BufReader::new(stream_data.as_slice());

        // Decrypt
        let decrypted_packet = ChaCha20Poly1305::decrypt(&ctx, &mut reader).await.unwrap();

        assert_eq!(decrypted_packet.payload, payload);
        assert_eq!(decrypted_packet.packet_length, packet.packet_length);
        assert_eq!(decrypted_packet.padding_length, packet.padding_length);
    }

    #[tokio::test]
    async fn test_encrypt_different_sequences() {
        let enc_key = vec![0x42u8; 64];
        let payload = b"test payload".to_vec();

        let ctx1 = CipherCtx {
            seq: 1,
            iv: vec![],
            enc_key: enc_key.clone(),
            int_key: vec![],
            _cipher: PhantomData,
        };

        let ctx2 = CipherCtx {
            seq: 2,
            iv: vec![],
            enc_key,
            int_key: vec![],
            _cipher: PhantomData,
        };

        let packet = Packet::<ChaCha20Poly1305>::from_payload(&ctx1, payload)
            .await
            .unwrap();

        let (encrypted1, mac1) = ChaCha20Poly1305::encrypt(
            &ctx1,
            packet.packet_length,
            packet.padding_length,
            &packet.payload,
            &packet.random_padding,
        )
        .await
        .unwrap();

        let (encrypted2, mac2) = ChaCha20Poly1305::encrypt(
            &ctx2,
            packet.packet_length,
            packet.padding_length,
            &packet.payload,
            &packet.random_padding,
        )
        .await
        .unwrap();

        // Different sequence numbers should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);
        assert_ne!(mac1, mac2);
    }

    #[tokio::test]
    async fn test_decrypt_invalid_mac() {
        let enc_key = vec![0x42u8; 64];
        let ctx = CipherCtx {
            seq: 1,
            iv: vec![],
            enc_key,
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payload = b"test payload".to_vec();
        let packet = Packet::<ChaCha20Poly1305>::from_payload(&ctx, payload)
            .await
            .unwrap();

        let (encrypted, mut mac) = ChaCha20Poly1305::encrypt(
            &ctx,
            packet.packet_length,
            packet.padding_length,
            &packet.payload,
            &packet.random_padding,
        )
        .await
        .unwrap();

        // Corrupt the MAC
        mac[0] ^= 0xFF;

        let mut stream_data = vec![];
        stream_data.extend_from_slice(&encrypted);
        stream_data.extend_from_slice(&mac);
        let mut reader = BufReader::new(stream_data.as_slice());

        let result = ChaCha20Poly1305::decrypt(&ctx, &mut reader).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid MAC"));
    }

    #[tokio::test]
    async fn test_decrypt_invalid_packet_length() {
        let enc_key = vec![0x42u8; 64];
        let ctx = CipherCtx {
            seq: 1,
            iv: vec![],
            enc_key,
            int_key: vec![],
            _cipher: PhantomData,
        };

        // Create a fake encrypted packet with invalid length (too small)
        let mut stream_data = vec![];

        // Encrypt a packet length that's too small
        let fake_length = (MIN_PACKET_LENGTH - 1) as u32;
        let mut length_bytes = vec![];
        length_bytes.extend_from_slice(&fake_length.to_be_bytes());

        let k_length = ctx.enc_key[32..].to_vec();
        let mut nonce = vec![0u8; 4];
        let mut writer = BufWriter::new(&mut nonce);
        writer.write_u32(ctx.seq).await.unwrap();
        writer.flush().await.unwrap();

        let mut cipher =
            <ChaCha20Legacy as KeyIvInit>::new(k_length.as_slice().into(), nonce.as_slice().into());
        cipher.apply_keystream(&mut length_bytes);

        stream_data.extend_from_slice(&length_bytes);

        let mut reader = BufReader::new(stream_data.as_slice());
        let result = ChaCha20Poly1305::decrypt(&ctx, &mut reader).await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid packet length"));
    }

    #[tokio::test]
    async fn test_packet_to_stream() {
        let enc_key = vec![0x42u8; 64];
        let ctx = CipherCtx {
            seq: 1,
            iv: vec![],
            enc_key,
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payload = b"Hello, world!".to_vec();
        let packet = Packet::<ChaCha20Poly1305>::from_payload(&ctx, payload.clone())
            .await
            .unwrap();

        let mut stream_data = vec![];
        {
            let mut writer = BufWriter::new(&mut stream_data);
            packet.to_stream(&ctx, &mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Verify we can decrypt what we wrote
        let mut reader = BufReader::new(stream_data.as_slice());
        let decrypted_packet = Packet::<ChaCha20Poly1305>::from_stream(&ctx, &mut reader)
            .await
            .unwrap();

        assert_eq!(decrypted_packet.payload, payload);
    }

    #[tokio::test]
    async fn test_empty_payload() {
        let enc_key = vec![0x42u8; 64];
        let ctx = CipherCtx {
            seq: 1,
            iv: vec![],
            enc_key,
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payload = vec![];
        let packet = Packet::<ChaCha20Poly1305>::from_payload(&ctx, payload.clone())
            .await
            .unwrap();

        let (encrypted, mac) = ChaCha20Poly1305::encrypt(
            &ctx,
            packet.packet_length,
            packet.padding_length,
            &packet.payload,
            &packet.random_padding,
        )
        .await
        .unwrap();

        let mut stream_data = vec![];
        stream_data.extend_from_slice(&encrypted);
        stream_data.extend_from_slice(&mac);
        let mut reader = BufReader::new(stream_data.as_slice());

        let decrypted_packet = ChaCha20Poly1305::decrypt(&ctx, &mut reader).await.unwrap();
        assert_eq!(decrypted_packet.payload, payload);
    }

    #[tokio::test]
    async fn test_large_payload() {
        let enc_key = vec![0x42u8; 64];
        let ctx = CipherCtx {
            seq: 1,
            iv: vec![],
            enc_key,
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payload = vec![0xABu8; 1000]; // Large payload
        let packet = Packet::<ChaCha20Poly1305>::from_payload(&ctx, payload.clone())
            .await
            .unwrap();

        let (encrypted, mac) = ChaCha20Poly1305::encrypt(
            &ctx,
            packet.packet_length,
            packet.padding_length,
            &packet.payload,
            &packet.random_padding,
        )
        .await
        .unwrap();

        let mut stream_data = vec![];
        stream_data.extend_from_slice(&encrypted);
        stream_data.extend_from_slice(&mac);
        let mut reader = BufReader::new(stream_data.as_slice());

        let decrypted_packet = ChaCha20Poly1305::decrypt(&ctx, &mut reader).await.unwrap();
        assert_eq!(decrypted_packet.payload, payload);
    }

    #[tokio::test]
    async fn test_peek_opcode() {
        let enc_key = vec![0x42u8; 64];
        let ctx = CipherCtx {
            seq: 1,
            iv: vec![],
            enc_key,
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payload = vec![0x14, 0x01, 0x02, 0x03]; // First byte is opcode
        let packet = Packet::<ChaCha20Poly1305>::from_payload(&ctx, payload)
            .await
            .unwrap();

        assert_eq!(packet.peek_opcode(), Some(0x14));

        // Test empty payload
        let empty_packet = Packet::<ChaCha20Poly1305>::from_payload(&ctx, vec![])
            .await
            .unwrap();
        assert_eq!(empty_packet.peek_opcode(), None);
    }
}
