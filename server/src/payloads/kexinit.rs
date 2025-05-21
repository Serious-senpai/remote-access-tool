use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use tokio::io::AsyncWriteExt;

use crate::config;
use crate::payloads::format::PayloadFormat;
use crate::utils::{read_string, write_string};

#[derive(Debug, Clone)]
pub struct KexInit {
    pub cookie: Vec<u8>,
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
    pub languages_client_to_server: Vec<String>,
    pub languages_server_to_client: Vec<String>,
    pub first_kex_packet_follows: bool,
    pub reserved: u32,
}

impl PayloadFormat for KexInit {
    const OPCODE: u8 = 20;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized,
        S: tokio::io::AsyncReadExt + Unpin,
    {
        let opcode = stream.read_u8().await?;
        Self::check_opcode(opcode)?;

        let mut cookie = vec![0u8; 16];
        stream.read_exact(&mut cookie).await?;

        let kex_algorithms = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();
        let server_host_key_algorithms = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();
        let encryption_algorithms_client_to_server = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();
        let encryption_algorithms_server_to_client = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();
        let mac_algorithms_client_to_server = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();
        let mac_algorithms_server_to_client = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();
        let compression_algorithms_client_to_server =
            String::from_utf8(read_string(stream).await?)?
                .split(",")
                .map(String::from)
                .collect();
        let compression_algorithms_server_to_client =
            String::from_utf8(read_string(stream).await?)?
                .split(",")
                .map(String::from)
                .collect();
        let languages_client_to_server = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();
        let languages_server_to_client = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();

        let first_kex_packet_follows = stream.read_u8().await? != 0;
        let reserved = stream.read_u32().await?;

        Ok(Self {
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
            reserved,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn std::error::Error>>
    where
        Self: Sized,
        S: AsyncWriteExt + Unpin,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_all(&self.cookie).await?;

        write_string(stream, self.kex_algorithms.join(",").as_bytes()).await?;
        write_string(stream, self.server_host_key_algorithms.join(",").as_bytes()).await?;
        write_string(
            stream,
            self.encryption_algorithms_client_to_server
                .join(",")
                .as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self.encryption_algorithms_server_to_client
                .join(",")
                .as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self.mac_algorithms_client_to_server.join(",").as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self.mac_algorithms_server_to_client.join(",").as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self.compression_algorithms_client_to_server
                .join(",")
                .as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self.compression_algorithms_server_to_client
                .join(",")
                .as_bytes(),
        )
        .await?;
        write_string(stream, self.languages_client_to_server.join(",").as_bytes()).await?;
        write_string(stream, self.languages_server_to_client.join(",").as_bytes()).await?;

        stream.write_u8(self.first_kex_packet_follows as u8).await?;
        stream.write_u32(self.reserved).await?;

        Ok(())
    }
}

impl KexInit {
    pub fn new() -> Self {
        let mut rng = StdRng::from_os_rng();
        let mut cookie = vec![0u8; 16];
        rng.fill_bytes(&mut cookie);

        Self {
            cookie,
            kex_algorithms: vec![config::KEX_ALGORITHMS.to_string()],
            server_host_key_algorithms: vec![config::SERVER_HOST_KEY_ALGORITHMS.to_string()],
            encryption_algorithms_client_to_server: vec![
                config::ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER.to_string(),
            ],
            encryption_algorithms_server_to_client: vec![
                config::ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT.to_string(),
            ],
            mac_algorithms_client_to_server: vec![
                config::MAC_ALGORITHMS_CLIENT_TO_SERVER.to_string()
            ],
            mac_algorithms_server_to_client: vec![
                config::MAC_ALGORITHMS_SERVER_TO_CLIENT.to_string()
            ],
            compression_algorithms_client_to_server: vec![
                config::COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER.to_string(),
            ],
            compression_algorithms_server_to_client: vec![
                config::COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT.to_string(),
            ],
            languages_client_to_server: vec![config::LANGUAGES_CLIENT_TO_SERVER.to_string()],
            languages_server_to_client: vec![config::LANGUAGES_SERVER_TO_CLIENT.to_string()],
            first_kex_packet_follows: false,
            reserved: 0,
        }
    }
}
