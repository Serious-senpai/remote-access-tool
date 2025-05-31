use std::error::Error;

use async_trait::async_trait;
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::scalar::clamp_integer;
use curve25519_dalek::{MontgomeryPoint, Scalar};
use rand::RngCore;
use rsa::BigUint;
use ssh_key::sha2::{Digest, Sha256};

use super::super::super::errors::RuntimeError;
use super::super::super::utils::{write_biguint_vec, write_string_vec};
use super::KexAlgorithm;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Curve25519Sha256 {
    pub public_key: [u8; 32],
    pub private_seed: [u8; 32],
    pub comment: String,
}

#[async_trait]
impl KexAlgorithm for Curve25519Sha256 {
    fn new(comment: impl Into<String>) -> Self {
        let mut rng = rand::thread_rng();

        let mut private_seed = [0u8; 32];
        rng.fill_bytes(&mut private_seed);
        private_seed = clamp_integer(private_seed);

        let secret_scalar = Scalar::from_bytes_mod_order(private_seed);
        let public_key = X25519_BASEPOINT * secret_scalar;
        let public_key = public_key.to_bytes();

        Self {
            public_key,
            private_seed,
            comment: comment.into(),
        }
    }

    fn hash(data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }

    fn shared_secret(
        our_private: Vec<u8>,
        their_public: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
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
