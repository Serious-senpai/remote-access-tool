use std::error::Error;

use async_trait::async_trait;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha512;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use ssh_key::private::KeypairData;
use ssh_key::PrivateKey;
use tokio::io::BufReader;

use crate::cipher::hostkey::HostKeyAlgorithm;
use crate::errors::RuntimeError;
use crate::utils::read_biguint;

pub struct RsaSha512;

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

#[cfg(test)]
mod tests {
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::RandomizedSigner;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use tokio::io::{AsyncWriteExt, BufWriter};

    use super::*;
    use crate::utils::write_biguint;

    fn create_test_rsa_keypair() -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        (private_key, public_key)
    }

    async fn create_server_host_key_data(public_key: &RsaPublicKey) -> Vec<u8> {
        let mut buffer = Vec::new();
        {
            let mut writer = BufWriter::new(&mut buffer);
            write_biguint(&mut writer, public_key.e()).await.unwrap();
            write_biguint(&mut writer, public_key.n()).await.unwrap();
            writer.flush().await.unwrap();
        }
        buffer
    }

    #[tokio::test]
    async fn test_verify_valid_signature() {
        let (private_key, public_key) = create_test_rsa_keypair();
        let exchange_hash = b"test exchange hash";

        // Create signature using the private key
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::<Sha512>::new(private_key);
        let signature = signing_key.sign_with_rng(&mut rng, exchange_hash);

        // Create server host key data
        let server_host_key = create_server_host_key_data(&public_key).await;

        // Verify the signature
        let result =
            RsaSha512::verify(exchange_hash, &signature.to_bytes(), &server_host_key).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_invalid_signature() {
        let (_, public_key) = create_test_rsa_keypair();
        let exchange_hash = b"test exchange hash";
        let invalid_signature = vec![0u8; 256]; // Invalid signature

        let server_host_key = create_server_host_key_data(&public_key).await;

        let result = RsaSha512::verify(exchange_hash, &invalid_signature, &server_host_key).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_wrong_hash() {
        let (private_key, public_key) = create_test_rsa_keypair();
        let original_hash = b"original hash";
        let different_hash = b"different hash";

        // Sign with original hash
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::<Sha512>::new(private_key);
        let signature = signing_key.sign_with_rng(&mut rng, original_hash);

        let server_host_key = create_server_host_key_data(&public_key).await;

        // Try to verify with different hash
        let result =
            RsaSha512::verify(different_hash, &signature.to_bytes(), &server_host_key).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_malformed_server_host_key() {
        let exchange_hash = b"test hash";
        let signature = vec![0u8; 256];
        let malformed_key = vec![0u8; 10]; // Too short to contain valid RSA key data

        let result = RsaSha512::verify(exchange_hash, &signature, &malformed_key).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_empty_signature() {
        let (_, public_key) = create_test_rsa_keypair();
        let exchange_hash = b"test hash";
        let empty_signature = vec![];

        let server_host_key = create_server_host_key_data(&public_key).await;

        let result = RsaSha512::verify(exchange_hash, &empty_signature, &server_host_key).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_algorithm_constants() {
        assert_eq!(RsaSha512::HOST_KEY_ALGORITHM, "ssh-rsa");
        assert_eq!(RsaSha512::SIGNATURE_ALGORITHM, "rsa-sha2-512");
    }
}
