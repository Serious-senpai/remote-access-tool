use std::error::Error;

use async_trait::async_trait;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha512;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use ssh_key::private::KeypairData;
use ssh_key::PrivateKey;
use tokio::io::BufReader;

use super::super::super::errors::RuntimeError;
use super::super::super::utils::read_biguint;
use super::HostKeyAlgorithm;

pub struct RsaSha512 {}

#[async_trait]
impl HostKeyAlgorithm for RsaSha512 {
    const HOST_KEY_ALGORITHM: &str = "ssh-rsa";
    const SIGNATURE_ALGORITHM: &str = "rsa-sha2-512";

    async fn verify(
        exchange_hash: &[u8],
        signature: &[u8],
        server_host_key: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut reader = BufReader::new(server_host_key);
        let e = read_biguint(&mut reader).await?;
        let n = read_biguint(&mut reader).await?;

        let verify_key = VerifyingKey::<Sha512>::new(RsaPublicKey::new(n, e)?);
        let signature = Signature::try_from(signature)?;

        Ok(verify_key.verify(exchange_hash, &signature)?)
    }

    async fn sign(
        exchange_hash: &[u8],
        private_key: &PrivateKey,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        if let KeypairData::Rsa(key_data) = private_key.key_data() {
            let p = BigUint::from_bytes_be(
                key_data
                    .private
                    .p
                    .as_positive_bytes()
                    .ok_or_else(|| RuntimeError::new("Invalid RSA prime p"))?,
            );
            let q = BigUint::from_bytes_be(
                key_data
                    .private
                    .q
                    .as_positive_bytes()
                    .ok_or_else(|| RuntimeError::new("Invalid RSA prime q"))?,
            );
            let n = &p * &q;
            let e = BigUint::from_bytes_be(
                key_data
                    .public
                    .e
                    .as_positive_bytes()
                    .ok_or_else(|| RuntimeError::new("Invalid RSA public exponent e"))?,
            );
            let d = BigUint::from_bytes_be(
                key_data
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
        } else {
            Err(RuntimeError::new("The provided key is not an RSA key"))?
        }
    }
}
