use std::error::Error;

use async_trait::async_trait;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::sha2::Sha512;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use tokio::io::BufReader;

use super::super::super::config;
use super::super::super::utils::read_biguint;
use super::HostKeyAlgorithm;

pub struct RsaSha2512 {}

#[async_trait]
impl HostKeyAlgorithm for RsaSha2512 {
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

        Ok(verify_key.verify(&exchange_hash, &signature)?)
    }
}
