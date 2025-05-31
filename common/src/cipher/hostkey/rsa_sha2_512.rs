use std::error::Error;

use async_trait::async_trait;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha512;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use ssh_key::private::RsaKeypair;
use tokio::io::BufReader;

use super::super::super::config;
use super::super::super::errors::RuntimeError;
use super::super::super::utils::read_biguint;
use super::HostKeyAlgorithm;

pub struct RsaSha2512 {}

#[async_trait]
impl HostKeyAlgorithm for RsaSha2512 {
    type RKey = RsaKeypair;

    async fn verify(
        signature_algorithm: &str,
        exchange_hash: &[u8],
        signature: &[u8],
        server_host_key: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(signature_algorithm, config::SERVER_HOST_KEY_ALGORITHMS);

        let mut reader = BufReader::new(server_host_key);
        let e = read_biguint(&mut reader).await?;
        let n = read_biguint(&mut reader).await?;

        let verify_key = VerifyingKey::<Sha512>::new(RsaPublicKey::new(n, e)?);
        let signature = Signature::try_from(signature)?;

        Ok(verify_key.verify(exchange_hash, &signature)?)
    }

    async fn sign(
        signature_algorithm: &str,
        exchange_hash: &[u8],
        private_key: &Self::RKey,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        assert_eq!(signature_algorithm, config::SERVER_HOST_KEY_ALGORITHMS);

        let p = BigUint::from_bytes_be(
            private_key
                .private
                .p
                .as_positive_bytes()
                .ok_or_else(|| RuntimeError::new("Invalid RSA prime p"))?,
        );
        let q = BigUint::from_bytes_be(
            private_key
                .private
                .q
                .as_positive_bytes()
                .ok_or_else(|| RuntimeError::new("Invalid RSA prime q"))?,
        );
        let n = &p * &q;
        let e = BigUint::from_bytes_be(
            private_key
                .public
                .e
                .as_positive_bytes()
                .ok_or_else(|| RuntimeError::new("Invalid RSA public exponent e"))?,
        );
        let d = BigUint::from_bytes_be(
            private_key
                .private
                .d
                .as_positive_bytes()
                .ok_or_else(|| RuntimeError::new("Invalid RSA private exponent d"))?,
        );

        let usable_private_key = RsaPrivateKey::from_components(n, e, d, vec![p, q])?;

        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::<Sha512>::new(usable_private_key);
        let signature = signing_key.sign_with_rng(&mut rng, exchange_hash);
        Ok(signature.to_bytes().to_vec())
    }
}
