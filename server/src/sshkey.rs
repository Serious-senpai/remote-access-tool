use std::error::Error;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::Scalar;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, BufReader};

use crate::errors::{IntegrityError, RuntimeError};
use crate::utils::{read_exact, read_string};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519KeyPair {
    pub public_key: [u8; 32],
    pub private_seed: [u8; 32],
    pub comment: String,
}

impl Ed25519KeyPair {
    const _PRIVATE_KEY_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const _PRIVATE_KEY_FOOTER: &str = "-----END OPENSSH PRIVATE KEY-----";

    async fn _check_header_footer(file: &mut File) -> Result<String, IntegrityError> {
        let mut last_line = vec![];
        loop {
            let byte = file
                .read_u8()
                .await
                .map_err(|_| IntegrityError::raw("Unexpected EOF when finding header"))?;

            if byte == b'\n' {
                let line = String::from_utf8(last_line);
                if line != Ok(String::from(Self::_PRIVATE_KEY_HEADER)) {
                    return Err(IntegrityError::raw("Missing OpenSSH private key header"));
                }

                last_line = vec![];
                break;
            }

            last_line.push(byte);
        }

        let mut buf = vec![];
        last_line.clear();
        loop {
            let byte = file
                .read_u8()
                .await
                .map_err(|_| IntegrityError::raw("Unexpected EOF when finding footer"))?;

            if byte == b'\n' {
                let last_line_length = last_line.len();
                let line = String::from_utf8(last_line);
                if line == Ok(String::from(Self::_PRIVATE_KEY_FOOTER)) {
                    for _ in 0..last_line_length {
                        buf.pop();
                    }
                    break;
                }

                last_line = vec![];
            } else {
                last_line.push(byte);
                buf.push(byte);
            }
        }

        Ok(String::from_utf8(buf)
            .map_err(|_| IntegrityError::raw("Invalid UTF-8 in OpenSSH private key file"))?)
    }

    const BUFFER_PREFIX: &[u8] = b"openssh-key-v1\x00\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x33\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20";
    const SSH_ED25519: &[u8] = b"\x00\x00\x00\x0bssh-ed25519";

    pub async fn parse(file: &mut File) -> Result<Ed25519KeyPair, Box<dyn Error>> {
        let buffer = STANDARD.decode(Self::_check_header_footer(file).await?)?;

        fn _unsupported_error<T>() -> Result<T, Box<dyn Error>> {
            Err(RuntimeError::new(
                "Only ssh-ed25519, ciphername = kdfname = none, number_of_keys = 1 is supported.",
            ))?
        }

        let mut reader = BufReader::new(buffer.as_slice());
        for &c in Self::BUFFER_PREFIX {
            let byte = reader.read_u8().await?;
            if byte != c {
                return _unsupported_error();
            }
        }

        let public_key = read_exact(&mut reader, 32).await?;

        let private_key_data = read_string(&mut reader).await?;
        let mut reader = BufReader::new(private_key_data.as_slice());

        let checkint1 = reader.read_u32().await?;
        let checkint2 = reader.read_u32().await?;
        if checkint1 != checkint2 {
            return Err(IntegrityError::raw("Check integers do not match"))?;
        }

        for &c in Ed25519KeyPair::SSH_ED25519 {
            if reader.read_u8().await? != c {
                return _unsupported_error();
            }
        }

        let public_keys_mismatch = Err(IntegrityError::raw("Public keys do not match"));
        if read_string(&mut reader).await? != public_key {
            return public_keys_mismatch?;
        }

        let mut private_seed = read_string(&mut reader).await?;
        if private_seed.split_off(32) != public_key {
            return public_keys_mismatch?;
        }

        let comment = String::from_utf8(read_string(&mut reader).await?)?;

        Ok(Ed25519KeyPair {
            public_key: public_key
                .try_into()
                .map_err(|_| RuntimeError::new("Invalid public key length"))?,
            private_seed: private_seed
                .try_into()
                .map_err(|_| RuntimeError::new("Invalid private key length"))?,
            comment,
        })
    }

    pub fn new() -> Self {
        let mut rng = StdRng::from_os_rng();

        let mut private_seed = [0u8; 32];
        rng.fill_bytes(&mut private_seed);

        // Clamp private key
        private_seed[0] &= 248;
        private_seed[31] &= 127;
        private_seed[31] |= 64;

        let secret_scalar = Scalar::from_bytes_mod_order(private_seed.clone());
        let public_key = X25519_BASEPOINT * secret_scalar;
        let public_key = public_key.to_bytes();

        Self {
            public_key,
            private_seed,
            comment: String::from(""),
        }
    }
}
