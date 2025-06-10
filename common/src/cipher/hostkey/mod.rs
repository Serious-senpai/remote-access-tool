pub mod rsa_sha2_512;

use std::error::Error;
use std::path::PathBuf;

use async_trait::async_trait;
use ssh_key::private::KeypairData;
use ssh_key::PrivateKey;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::utils::write_string;

pub async fn read_host_key(
    path: &PathBuf,
) -> Result<(Vec<u8>, PrivateKey), Box<dyn Error + Send + Sync>> {
    let mut file = File::open(path).await?;
    let mut data = vec![];
    file.read_to_end(&mut data).await?;

    let key = PrivateKey::from_openssh(&data)?;
    match key.key_data() {
        KeypairData::Rsa(keypair) => {
            data.clear();
            write_string(&mut data, keypair.public.e.as_bytes()).await?;
            write_string(&mut data, keypair.public.n.as_bytes()).await?;
            Ok((data, key))
        }
        _ => unimplemented!(),
    }
}

#[async_trait]
pub trait HostKeyAlgorithm: Send + Sync {
    const HOST_KEY_ALGORITHM: &str;
    const SIGNATURE_ALGORITHM: &str;

    async fn verify(
        exchange_hash: &[u8],
        signature: &[u8],
        server_host_key: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    async fn sign(
        exchange_hash: &[u8],
        private_key: &PrivateKey,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>;
}
