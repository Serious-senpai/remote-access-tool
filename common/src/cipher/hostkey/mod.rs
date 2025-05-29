pub mod rsa_sha2_512;

use std::error::Error;

use async_trait::async_trait;

#[async_trait]
pub trait HostKeyAlgorithm {
    async fn verify(
        signature_algorithm: &str,
        exchange_hash: &[u8],
        signature: &[u8],
        server_host_key: &[u8],
    ) -> Result<(), Box<dyn Error>>;
}
