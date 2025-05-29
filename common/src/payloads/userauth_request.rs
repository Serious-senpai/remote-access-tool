use std::error::Error;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::utils::{read_string, write_string};
use super::PayloadFormat;

#[derive(Debug, Clone)]
pub enum UserauthMethod {
    PublicKey {
        algorithm: String,
        key: Vec<u8>,
    },
    Password {
        password: String,
    },
    HostBased {
        algorithm: String,
        key_certificate: Vec<u8>,
        client_host: String,
        username: String,
        signature: Vec<u8>,
    },
    None,
}

impl UserauthMethod {
    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        Self: Sized,
        S: AsyncWriteExt + Unpin,
    {
        match self {
            &Self::PublicKey {
                ref algorithm,
                ref key,
            } => {
                write_string(stream, b"publickey").await?;
                stream.write_u8(1).await?;
                write_string(stream, algorithm.as_bytes()).await?;
                write_string(stream, &key).await?;
            }
            &Self::Password { ref password } => {
                write_string(stream, b"password").await?;
                stream.write_u8(0).await?;
                write_string(stream, password.as_bytes()).await?;
            }
            &Self::HostBased {
                ref algorithm,
                ref key_certificate,
                ref client_host,
                ref username,
                ref signature,
            } => {
                write_string(stream, b"hostbased").await?;
                write_string(stream, algorithm.as_bytes()).await?;
                write_string(stream, &key_certificate).await?;
                write_string(stream, client_host.as_bytes()).await?;
                write_string(stream, username.as_bytes()).await?;
                write_string(stream, &signature).await?;
            }
            &Self::None => {
                write_string(stream, b"none").await?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct UserauthRequest {
    pub username: String,
    pub service_name: String,
    pub method_name: UserauthMethod,
}

#[async_trait]
impl PayloadFormat for UserauthRequest {
    const OPCODE: u8 = 50;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
    where
        S: AsyncReadExt + Send + Unpin,
        Self: Sized,
    {
        let opcode = stream.read_u8().await?;
        Self::_check_opcode(opcode)?;

        let username = read_string(stream).await?;
        let username = String::from_utf8(username)?;

        let service_name = read_string(stream).await?;
        let service_name = String::from_utf8(service_name)?;

        let method_name = read_string(stream).await?;
        let method_name = match method_name.as_slice() {
            b"publickey" => {
                assert_eq!(stream.read_u8().await?, 1);
                let algorithm = read_string(stream).await?;
                let algorithm = String::from_utf8(algorithm)?;
                let key = read_string(stream).await?;

                UserauthMethod::PublicKey { algorithm, key }
            }
            b"password" => {
                assert_eq!(stream.read_u8().await?, 0);
                let password = read_string(stream).await?;
                let password = String::from_utf8(password)?;

                UserauthMethod::Password { password }
            }
            b"hostbased" => {
                let algorithm = read_string(stream).await?;
                let algorithm = String::from_utf8(algorithm)?;

                let key_certificate = read_string(stream).await?;

                let client_host = read_string(stream).await?;
                let client_host = String::from_utf8(client_host)?;

                let username = read_string(stream).await?;
                let username = String::from_utf8(username)?;

                let signature = read_string(stream).await?;

                UserauthMethod::HostBased {
                    algorithm,
                    key_certificate,
                    client_host,
                    username,
                    signature,
                }
            }
            _ => UserauthMethod::None,
        };

        Ok(Self {
            username,
            service_name,
            method_name,
        })
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: AsyncWriteExt + Send + Unpin,
        Self: Sized,
    {
        stream.write_u8(Self::OPCODE).await?;
        write_string(stream, self.username.as_bytes()).await?;
        write_string(stream, self.service_name.as_bytes()).await?;
        self.method_name.to_stream(stream).await?;
        Ok(())
    }
}
