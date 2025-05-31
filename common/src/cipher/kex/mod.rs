pub mod curve25519_sha256;

use std::error::Error;

use async_trait::async_trait;

#[async_trait]
pub trait KexAlgorithm {
    fn new(comment: impl Into<String>) -> Self;
    fn hash(data: &[u8]) -> Vec<u8>;
    fn shared_secret(
        our_private: Vec<u8>,
        their_public: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error>>;

    #[allow(clippy::too_many_arguments)]
    async fn exchange_hash(
        client_id: &[u8],
        server_id: &[u8],
        client_kexinit: &[u8],
        server_kexinit: &[u8],
        server_host_key_payload: &[u8],
        client_public_key: &[u8],
        server_public_key: &[u8],
        shared_secret: &[u8],
    ) -> Vec<u8>;
}
