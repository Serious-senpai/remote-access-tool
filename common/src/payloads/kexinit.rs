use std::error::Error;

use async_trait::async_trait;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::cipher::encryption::Cipher;
use super::super::cipher::hostkey::HostKeyAlgorithm;
use super::super::cipher::kex::KexAlgorithm;
use super::super::utils::{read_string, write_string};
use super::PayloadFormat;

#[derive(Debug, Clone)]
pub struct KexInit {
    _cookie: Vec<u8>,
    _kex_algorithms: Vec<String>,
    _server_host_key_algorithms: Vec<String>,
    _encryption_algorithms_client_to_server: Vec<String>,
    _encryption_algorithms_server_to_client: Vec<String>,
    _mac_algorithms_client_to_server: Vec<String>,
    _mac_algorithms_server_to_client: Vec<String>,
    _compression_algorithms_client_to_server: Vec<String>,
    _compression_algorithms_server_to_client: Vec<String>,
    _languages_client_to_server: Vec<String>,
    _languages_server_to_client: Vec<String>,
    _first_kex_packet_follows: bool,
    _reserved: u32,
}

#[async_trait]
impl PayloadFormat for KexInit {
    const OPCODE: u8 = 20;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let mut _cookie = vec![0u8; 16];
        stream.read_exact(&mut _cookie).await?;

        let _kex_algorithms = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();
        let _server_host_key_algorithms = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();
        let _encryption_algorithms_client_to_server =
            String::from_utf8(read_string(stream).await?)?
                .split(",")
                .map(String::from)
                .collect();
        let _encryption_algorithms_server_to_client =
            String::from_utf8(read_string(stream).await?)?
                .split(",")
                .map(String::from)
                .collect();
        let _mac_algorithms_client_to_server = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();
        let _mac_algorithms_server_to_client = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();
        let _compression_algorithms_client_to_server =
            String::from_utf8(read_string(stream).await?)?
                .split(",")
                .map(String::from)
                .collect();
        let _compression_algorithms_server_to_client =
            String::from_utf8(read_string(stream).await?)?
                .split(",")
                .map(String::from)
                .collect();
        let _languages_client_to_server = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();
        let _languages_server_to_client = String::from_utf8(read_string(stream).await?)?
            .split(",")
            .map(String::from)
            .collect();

        let _first_kex_packet_follows = stream.read_u8().await? != 0;
        let _reserved = stream.read_u32().await?;

        Ok(Self {
            _cookie,
            _kex_algorithms,
            _server_host_key_algorithms,
            _encryption_algorithms_client_to_server,
            _encryption_algorithms_server_to_client,
            _mac_algorithms_client_to_server,
            _mac_algorithms_server_to_client,
            _compression_algorithms_client_to_server,
            _compression_algorithms_server_to_client,
            _languages_client_to_server,
            _languages_server_to_client,
            _first_kex_packet_follows,
            _reserved,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        stream.write_all(&self._cookie).await?;

        write_string(stream, self._kex_algorithms.join(",").as_bytes()).await?;
        write_string(
            stream,
            self._server_host_key_algorithms.join(",").as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self._encryption_algorithms_client_to_server
                .join(",")
                .as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self._encryption_algorithms_server_to_client
                .join(",")
                .as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self._mac_algorithms_client_to_server.join(",").as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self._mac_algorithms_server_to_client.join(",").as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self._compression_algorithms_client_to_server
                .join(",")
                .as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self._compression_algorithms_server_to_client
                .join(",")
                .as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self._languages_client_to_server.join(",").as_bytes(),
        )
        .await?;
        write_string(
            stream,
            self._languages_server_to_client.join(",").as_bytes(),
        )
        .await?;

        stream
            .write_u8(self._first_kex_packet_follows as u8)
            .await?;
        stream.write_u32(self._reserved).await?;

        Ok(())
    }
}

impl KexInit {
    pub fn new(
        kex_algorithms: Vec<impl Into<String>>,
        server_host_key_algorithms: Vec<impl Into<String>>,
        encryption_algorithms_client_to_server: Vec<impl Into<String>>,
        encryption_algorithms_server_to_client: Vec<impl Into<String>>,
        mac_algorithms_client_to_server: Vec<impl Into<String>>,
        mac_algorithms_server_to_client: Vec<impl Into<String>>,
        compression_algorithms_client_to_server: Vec<impl Into<String>>,
        compression_algorithms_server_to_client: Vec<impl Into<String>>,
        languages_client_to_server: Vec<impl Into<String>>,
        languages_server_to_client: Vec<impl Into<String>>,
        first_kex_packet_follows: bool,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let mut cookie = vec![0u8; 16];
        rng.fill_bytes(&mut cookie);

        fn convert(s: Vec<impl Into<String>>) -> Vec<String> {
            s.into_iter().map(Into::into).collect()
        }

        Self {
            _cookie: cookie,
            _kex_algorithms: convert(kex_algorithms),
            _server_host_key_algorithms: convert(server_host_key_algorithms),
            _encryption_algorithms_client_to_server: convert(
                encryption_algorithms_client_to_server,
            ),
            _encryption_algorithms_server_to_client: convert(
                encryption_algorithms_server_to_client,
            ),
            _mac_algorithms_client_to_server: convert(mac_algorithms_client_to_server),
            _mac_algorithms_server_to_client: convert(mac_algorithms_server_to_client),
            _compression_algorithms_client_to_server: convert(
                compression_algorithms_client_to_server,
            ),
            _compression_algorithms_server_to_client: convert(
                compression_algorithms_server_to_client,
            ),
            _languages_client_to_server: convert(languages_client_to_server),
            _languages_server_to_client: convert(languages_server_to_client),
            _first_kex_packet_follows: first_kex_packet_follows,
            _reserved: 0,
        }
    }

    pub fn kex_algorithms(&self) -> &[String] {
        &self._kex_algorithms
    }

    pub fn server_host_key_algorithms(&self) -> &[String] {
        &self._server_host_key_algorithms
    }

    pub fn encryption_algorithms_client_to_server(&self) -> &[String] {
        &self._encryption_algorithms_client_to_server
    }

    pub fn encryption_algorithms_server_to_client(&self) -> &[String] {
        &self._encryption_algorithms_server_to_client
    }

    pub fn mac_algorithms_client_to_server(&self) -> &[String] {
        &self._mac_algorithms_client_to_server
    }

    pub fn mac_algorithms_server_to_client(&self) -> &[String] {
        &self._mac_algorithms_server_to_client
    }

    pub fn compression_algorithms_client_to_server(&self) -> &[String] {
        &self._compression_algorithms_client_to_server
    }

    pub fn compression_algorithms_server_to_client(&self) -> &[String] {
        &self._compression_algorithms_server_to_client
    }

    pub fn languages_client_to_server(&self) -> &[String] {
        &self._languages_client_to_server
    }

    pub fn languages_server_to_client(&self) -> &[String] {
        &self._languages_server_to_client
    }

    pub fn first_kex_packet_follows(&self) -> bool {
        self._first_kex_packet_follows
    }

    pub fn reserved(&self) -> u32 {
        self._reserved
    }

    pub fn has_kex<K>(&self) -> bool
    where
        K: KexAlgorithm,
    {
        self._kex_algorithms.contains(&K::NAME.to_string())
    }

    pub fn has_host_key<H>(&self) -> bool
    where
        H: HostKeyAlgorithm,
    {
        self._server_host_key_algorithms
            .contains(&H::SIGNATURE_ALGORITHM.to_string())
    }

    pub fn has_encryption<C>(&self) -> bool
    where
        C: Cipher,
    {
        let check = C::NAME.to_string();
        self._encryption_algorithms_client_to_server
            .contains(&check)
            && self
                ._encryption_algorithms_server_to_client
                .contains(&check)
    }
}
