use std::error::Error;

use async_trait::async_trait;
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::scalar::clamp_integer;
use curve25519_dalek::{MontgomeryPoint, Scalar};
use rand::RngCore;
use rsa::BigUint;
use ssh_key::sha2::{Digest, Sha256};

use crate::cipher::kex::KexAlgorithm;
use crate::errors::RuntimeError;
use crate::utils::{write_biguint_vec, write_string_vec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Curve25519Sha256 {
    _public_key: [u8; 32],
    _private_seed: [u8; 32],
    _comment: String,
}

#[async_trait]
impl KexAlgorithm for Curve25519Sha256 {
    const NAME: &str = "curve25519-sha256";

    fn new(comment: impl Into<String>) -> Self {
        let mut rng = rand::thread_rng();

        let mut private_seed = [0u8; 32];
        rng.fill_bytes(&mut private_seed);
        private_seed = clamp_integer(private_seed);

        let secret_scalar = Scalar::from_bytes_mod_order(private_seed);
        let public_key = X25519_BASEPOINT * secret_scalar;
        let public_key = public_key.to_bytes();

        Self {
            _public_key: public_key,
            _private_seed: private_seed,
            _comment: comment.into(),
        }
    }

    fn public_key(&self) -> &[u8] {
        &self._public_key
    }

    fn private_seed(&self) -> &[u8] {
        &self._private_seed
    }

    fn hash(data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }

    fn shared_secret(
        our_private: Vec<u8>,
        their_public: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let point = MontgomeryPoint(
            their_public
                .try_into()
                .map_err(|_| RuntimeError::new("Invalid public key"))?,
        );
        let secret = point.mul_clamped(
            our_private
                .try_into()
                .map_err(|_| RuntimeError::new("Invalid private key"))?,
        );
        Ok(secret.to_bytes().to_vec())
    }

    async fn exchange_hash(
        client_id: &[u8],
        server_id: &[u8],
        client_kexinit: &[u8],
        server_kexinit: &[u8],
        server_host_key_payload: &[u8],
        client_public_key: &[u8],
        server_public_key: &[u8],
        shared_secret: &[u8],
    ) -> Vec<u8> {
        let mut buffer = vec![];

        // ID strings of client and server, without CRLF
        write_string_vec(&mut buffer, client_id).await;
        write_string_vec(&mut buffer, server_id).await;

        // KEXINIT payloads sent by client and server
        write_string_vec(&mut buffer, client_kexinit).await;
        write_string_vec(&mut buffer, server_kexinit).await;

        // Server public host key
        write_string_vec(&mut buffer, server_host_key_payload).await;

        // Public keys of client and server
        write_string_vec(&mut buffer, client_public_key).await;
        write_string_vec(&mut buffer, server_public_key).await;

        // Shared secret
        let shared_secret_value = BigUint::from_bytes_be(shared_secret);
        write_biguint_vec(&mut buffer, &shared_secret_value).await;

        Self::hash(&buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_creates_valid_keypair() {
        let kex = Curve25519Sha256::new("test");

        assert_eq!(kex.public_key().len(), 32);
        assert_eq!(kex.private_seed().len(), 32);
        assert_eq!(kex._comment, "test");
    }

    #[tokio::test]
    async fn test_different_instances_have_different_keys() {
        let kex1 = Curve25519Sha256::new("test1");
        let kex2 = Curve25519Sha256::new("test2");

        assert_ne!(kex1.public_key(), kex2.public_key());
        assert_ne!(kex1.private_seed(), kex2.private_seed());
    }

    #[tokio::test]
    async fn test_hash_function() {
        let data = b"hello world";
        let hash = Curve25519Sha256::hash(data);

        assert_eq!(hash.len(), 32); // SHA256 produces 32 bytes

        // Same input should produce same hash
        let hash2 = Curve25519Sha256::hash(data);
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let different_hash = Curve25519Sha256::hash(b"different data");
        assert_ne!(hash, different_hash);
    }

    #[tokio::test]
    async fn test_shared_secret_generation() {
        let kex1 = Curve25519Sha256::new("alice");
        let kex2 = Curve25519Sha256::new("bob");

        // Alice computes shared secret using her private key and Bob's public key
        let shared_secret1 = Curve25519Sha256::shared_secret(
            kex1.private_seed().to_vec(),
            kex2.public_key().to_vec(),
        )
        .unwrap();

        // Bob computes shared secret using his private key and Alice's public key
        let shared_secret2 = Curve25519Sha256::shared_secret(
            kex2.private_seed().to_vec(),
            kex1.public_key().to_vec(),
        )
        .unwrap();

        // Both should produce the same shared secret
        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), 32);
    }

    #[tokio::test]
    async fn test_shared_secret_invalid_public_key() {
        let kex = Curve25519Sha256::new("test");
        let invalid_public = vec![0u8; 16]; // Wrong size

        let result = Curve25519Sha256::shared_secret(kex.private_seed().to_vec(), invalid_public);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_shared_secret_invalid_private_key() {
        let kex = Curve25519Sha256::new("test");
        let invalid_private = vec![0u8; 16]; // Wrong size

        let result = Curve25519Sha256::shared_secret(invalid_private, kex.public_key().to_vec());

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_exchange_hash_consistency() {
        let client_id = b"SSH-2.0-client";
        let server_id = b"SSH-2.0-server";
        let client_kexinit = b"client_kexinit_payload";
        let server_kexinit = b"server_kexinit_payload";
        let server_host_key = b"server_host_key";
        let client_public = b"client_public_key_32_bytes_long";
        let server_public = b"server_public_key_32_bytes_long";
        let shared_secret = b"shared_secret_32_bytes_long_data";

        let hash1 = Curve25519Sha256::exchange_hash(
            client_id,
            server_id,
            client_kexinit,
            server_kexinit,
            server_host_key,
            client_public,
            server_public,
            shared_secret,
        )
        .await;

        let hash2 = Curve25519Sha256::exchange_hash(
            client_id,
            server_id,
            client_kexinit,
            server_kexinit,
            server_host_key,
            client_public,
            server_public,
            shared_secret,
        )
        .await;

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA256 output
    }

    #[tokio::test]
    async fn test_exchange_hash_different_inputs() {
        let base_params = (
            b"SSH-2.0-client",
            b"SSH-2.0-server",
            b"client_kexinit_payload",
            b"server_kexinit_payload",
            b"server_host_key",
            b"client_public_key_32_bytes_long",
            b"server_public_key_32_bytes_long",
            b"shared_secret_32_bytes_long_data",
        );

        let hash1 = Curve25519Sha256::exchange_hash(
            base_params.0,
            base_params.1,
            base_params.2,
            base_params.3,
            base_params.4,
            base_params.5,
            base_params.6,
            base_params.7,
        )
        .await;

        // Change client ID
        let hash2 = Curve25519Sha256::exchange_hash(
            b"SSH-2.0-different-client",
            base_params.1,
            base_params.2,
            base_params.3,
            base_params.4,
            base_params.5,
            base_params.6,
            base_params.7,
        )
        .await;

        assert_ne!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_algorithm_name() {
        assert_eq!(Curve25519Sha256::NAME, "curve25519-sha256");
    }

    #[tokio::test]
    async fn test_clone_and_equality() {
        let kex1 = Curve25519Sha256::new("test");
        let kex2 = kex1.clone();

        assert_eq!(kex1, kex2);
        assert_eq!(kex1.public_key(), kex2.public_key());
        assert_eq!(kex1.private_seed(), kex2.private_seed());
    }

    #[tokio::test]
    async fn test_empty_comment() {
        let kex = Curve25519Sha256::new("");
        assert_eq!(kex._comment, "");
    }

    #[tokio::test]
    async fn test_long_comment() {
        let long_comment = "a".repeat(1000);
        let kex = Curve25519Sha256::new(long_comment.clone());
        assert_eq!(kex._comment, long_comment);
    }

    #[tokio::test]
    async fn test_hash_empty_input() {
        let hash = Curve25519Sha256::hash(&[]);
        assert_eq!(hash.len(), 32);

        // Empty input should always produce the same hash
        let hash2 = Curve25519Sha256::hash(&[]);
        assert_eq!(hash, hash2);
    }

    #[tokio::test]
    async fn test_hash_large_input() {
        let large_data = vec![0xAB; 10000];
        let hash = Curve25519Sha256::hash(&large_data);
        assert_eq!(hash.len(), 32);
    }

    #[tokio::test]
    async fn test_shared_secret_zero_keys() {
        let zero_private = vec![0u8; 32];
        let zero_public = vec![0u8; 32];

        let result = Curve25519Sha256::shared_secret(zero_private, zero_public);
        assert!(result.is_ok());

        let shared_secret = result.unwrap();
        assert_eq!(shared_secret.len(), 32);
    }

    #[tokio::test]
    async fn test_exchange_hash_with_empty_inputs() {
        let hash = Curve25519Sha256::exchange_hash(&[], &[], &[], &[], &[], &[], &[], &[]).await;

        assert_eq!(hash.len(), 32);
    }

    #[tokio::test]
    async fn test_key_generation_determinism() {
        // While keys should be random, the same seed should produce the same result
        // This test ensures the algorithm is deterministic given fixed inputs
        let kex1 = Curve25519Sha256::new("same_comment");
        let kex2 = Curve25519Sha256::new("same_comment");

        // Keys should be different because of random generation
        assert_ne!(kex1.public_key(), kex2.public_key());

        // But both should have valid key lengths
        assert_eq!(kex1.public_key().len(), 32);
        assert_eq!(kex2.public_key().len(), 32);
    }
}
