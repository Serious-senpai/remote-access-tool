use std::error::Error;

use async_trait::async_trait;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cipher::encryption::{Cipher, CipherCtx};
use crate::packets::{Packet, MIN_PACKET_LENGTH, MIN_PADDING_LENGTH};

#[derive(Debug, Clone)]
pub struct NoneCipher;

#[async_trait]
impl Cipher for NoneCipher {
    const NAME: &str = "none";
    const IV_SIZE: usize = 0;
    const ENC_SIZE: usize = 0;
    const INT_SIZE: usize = 0;

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
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut padding);
        padding
    }

    async fn encrypt(
        _ctx: &CipherCtx<Self>,
        packet_length: u32,
        padding_length: u8,
        payload: &[u8],
        random_padding: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error + Send + Sync>>
    where
        Self: Sized,
    {
        let mut buffer = vec![];
        buffer.write_u32(packet_length).await?;
        buffer.write_u8(padding_length).await?;
        buffer.write_all(payload).await?;
        buffer.write_all(random_padding).await?;
        buffer.flush().await?;
        Ok((buffer, vec![]))
    }

    async fn decrypt<S>(
        _ctx: &CipherCtx<Self>,
        stream: &mut S,
    ) -> Result<Packet<Self>, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        Self::extract_raw_packet(stream).await
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_create_padding_minimum_length() {
        let padding = NoneCipher::create_padding(10);
        assert!(padding.len() >= MIN_PADDING_LENGTH);

        // Check that packet structure meets minimum requirements
        let total_size = 4 + 1 + 10 + padding.len(); // packet_length + padding_length + payload + padding
        assert!(total_size >= MIN_PACKET_LENGTH);
    }

    #[tokio::test]
    async fn test_create_padding_block_alignment() {
        let payload_size = 5;
        let padding = NoneCipher::create_padding(payload_size);

        // Total packet size should be aligned to 8-byte blocks
        let total_size = 4 + 1 + payload_size + padding.len();
        assert_eq!(total_size % 8, 0);
    }

    #[tokio::test]
    async fn test_create_padding_small_payload() {
        // Test with very small payload that requires minimum packet length
        let padding = NoneCipher::create_padding(1);
        let total_size = 4 + 1 + 1 + padding.len();
        assert!(total_size >= MIN_PACKET_LENGTH);
        assert!(padding.len() >= MIN_PADDING_LENGTH);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let ctx = CipherCtx {
            seq: 1,
            iv: vec![],
            enc_key: vec![],
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payload = b"Hello, world!".to_vec();
        let packet = Packet::<NoneCipher>::from_payload(&ctx, payload.clone())
            .await
            .unwrap();

        // Encrypt
        let (encrypted, mac) = NoneCipher::encrypt(
            &ctx,
            packet.packet_length,
            packet.padding_length,
            &packet.payload,
            &packet.random_padding,
        )
        .await
        .unwrap();

        // MAC should be empty for NoneCipher
        assert!(mac.is_empty());

        // Decrypt
        let mut reader = BufReader::new(encrypted.as_slice());
        let decrypted_packet = NoneCipher::decrypt(&ctx, &mut reader).await.unwrap();

        assert_eq!(decrypted_packet.payload, payload);
        assert_eq!(decrypted_packet.packet_length, packet.packet_length);
        assert_eq!(decrypted_packet.padding_length, packet.padding_length);
    }

    #[tokio::test]
    async fn test_empty_payload() {
        let ctx = CipherCtx {
            seq: 0,
            iv: vec![],
            enc_key: vec![],
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payload = vec![];
        let packet = Packet::<NoneCipher>::from_payload(&ctx, payload.clone())
            .await
            .unwrap();

        let (encrypted, mac) = NoneCipher::encrypt(
            &ctx,
            packet.packet_length,
            packet.padding_length,
            &packet.payload,
            &packet.random_padding,
        )
        .await
        .unwrap();

        assert!(mac.is_empty());

        let mut reader = BufReader::new(encrypted.as_slice());
        let decrypted_packet = NoneCipher::decrypt(&ctx, &mut reader).await.unwrap();

        assert_eq!(decrypted_packet.payload, payload);
        assert!(decrypted_packet.payload.is_empty());
    }

    #[tokio::test]
    async fn test_large_payload() {
        let ctx = CipherCtx {
            seq: 42,
            iv: vec![],
            enc_key: vec![],
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payload = vec![0xAB; 2048]; // Large payload
        let packet = Packet::<NoneCipher>::from_payload(&ctx, payload.clone())
            .await
            .unwrap();

        let (encrypted, mac) = NoneCipher::encrypt(
            &ctx,
            packet.packet_length,
            packet.padding_length,
            &packet.payload,
            &packet.random_padding,
        )
        .await
        .unwrap();

        assert!(mac.is_empty());

        let mut reader = BufReader::new(encrypted.as_slice());
        let decrypted_packet = NoneCipher::decrypt(&ctx, &mut reader).await.unwrap();

        assert_eq!(decrypted_packet.payload, payload);
    }

    #[tokio::test]
    async fn test_packet_to_stream() {
        let ctx = CipherCtx {
            seq: 100,
            iv: vec![],
            enc_key: vec![],
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payload = b"Test packet streaming".to_vec();
        let packet = Packet::<NoneCipher>::from_payload(&ctx, payload.clone())
            .await
            .unwrap();

        // Write packet to stream
        let mut stream_data = vec![];
        {
            let mut writer = BufWriter::new(&mut stream_data);
            packet.to_stream(&ctx, &mut writer).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Read packet back from stream
        let mut reader = BufReader::new(stream_data.as_slice());
        let decrypted_packet = Packet::<NoneCipher>::from_stream(&ctx, &mut reader)
            .await
            .unwrap();

        assert_eq!(decrypted_packet.payload, payload);
    }

    #[tokio::test]
    async fn test_peek_opcode() {
        let ctx = CipherCtx {
            seq: 1,
            iv: vec![],
            enc_key: vec![],
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payload = vec![0x14, 0x01, 0x02, 0x03]; // First byte is opcode
        let packet = Packet::<NoneCipher>::from_payload(&ctx, payload)
            .await
            .unwrap();

        assert_eq!(packet.peek_opcode(), Some(0x14));

        // Test empty payload
        let empty_packet = Packet::<NoneCipher>::from_payload(&ctx, vec![])
            .await
            .unwrap();
        assert_eq!(empty_packet.peek_opcode(), None);
    }

    #[tokio::test]
    async fn test_padding_randomness() {
        // Test that padding is actually random (not all zeros)
        let padding1 = NoneCipher::create_padding(10);
        let padding2 = NoneCipher::create_padding(10);

        // Same length but likely different content due to randomness
        assert_eq!(padding1.len(), padding2.len());

        // Very unlikely to be identical if truly random
        // Note: This test could theoretically fail due to randomness, but probability is extremely low
        if padding1.len() > 4 {
            assert_ne!(padding1, padding2);
        }
    }

    #[tokio::test]
    async fn test_packet_structure_consistency() {
        let ctx = CipherCtx {
            seq: 1,
            iv: vec![],
            enc_key: vec![],
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payload = b"consistency test".to_vec();
        let packet = Packet::<NoneCipher>::from_payload(&ctx, payload.clone())
            .await
            .unwrap();

        // Verify packet structure
        let expected_length = 1 + payload.len() + packet.random_padding.len();
        assert_eq!(packet.packet_length as usize, expected_length);
        assert_eq!(packet.padding_length as usize, packet.random_padding.len());

        // Encrypt and verify structure in stream
        let (encrypted, _) = NoneCipher::encrypt(
            &ctx,
            packet.packet_length,
            packet.padding_length,
            &packet.payload,
            &packet.random_padding,
        )
        .await
        .unwrap();

        // Should be: packet_length(4) + padding_length(1) + payload + padding
        let expected_total = 4 + 1 + payload.len() + packet.random_padding.len();
        assert_eq!(encrypted.len(), expected_total);
    }

    #[tokio::test]
    async fn test_multiple_packets_same_context() {
        let ctx = CipherCtx {
            seq: 5,
            iv: vec![],
            enc_key: vec![],
            int_key: vec![],
            _cipher: PhantomData,
        };

        let payloads = vec![
            b"first packet".to_vec(),
            b"second packet with more data".to_vec(),
            b"third".to_vec(),
            vec![], // empty payload
        ];

        for payload in payloads {
            let packet = Packet::<NoneCipher>::from_payload(&ctx, payload.clone())
                .await
                .unwrap();

            let (encrypted, mac) = NoneCipher::encrypt(
                &ctx,
                packet.packet_length,
                packet.padding_length,
                &packet.payload,
                &packet.random_padding,
            )
            .await
            .unwrap();

            assert!(mac.is_empty());

            let mut reader = BufReader::new(encrypted.as_slice());
            let decrypted_packet = NoneCipher::decrypt(&ctx, &mut reader).await.unwrap();

            assert_eq!(decrypted_packet.payload, payload);
        }
    }
}
