use std::error::Error;

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct SSHPacket {
    pub packet_length: u32,
    pub padding_length: u8,
    pub payload: Vec<u8>,
    pub random_padding: Vec<u8>,
    pub mac: Vec<u8>, // chacha20-poly1305@openssh.com does not need MAC
}

impl SSHPacket {
    pub fn from_payload(payload: Vec<u8>) -> Self {
        let mut random_padding = vec![0u8; 4];
        while (5 + payload.len() + random_padding.len()) % 8 != 0 {
            random_padding.push(0);
        }

        let mut rng = StdRng::from_os_rng();
        rng.fill_bytes(&mut random_padding);

        let packet_length = (1 + payload.len() + random_padding.len()) as u32;
        Self {
            packet_length,
            padding_length: random_padding.len() as u8,
            payload: payload,
            random_padding,
            mac: vec![],
        }
    }

    pub async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
    where
        S: AsyncReadExt + Unpin,
    {
        let packet_length = stream.read_u32().await?;
        let padding_length = stream.read_u8().await?;

        let mut payload = vec![0u8; packet_length as usize - padding_length as usize - 1];
        stream.read_exact(&mut payload).await?;

        let mut random_padding = vec![0u8; padding_length as usize];
        stream.read_exact(&mut random_padding).await?;

        Ok(Self {
            packet_length,
            padding_length,
            payload: payload.to_vec(),
            random_padding: random_padding.to_vec(),
            mac: vec![],
        })
    }

    pub async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: AsyncWriteExt + Unpin,
    {
        stream.write_u32(self.packet_length).await?;
        stream.write_u8(self.padding_length).await?;
        stream.write_all(&self.payload).await?;
        stream.write_all(&self.random_padding).await?;
        stream.write_all(&self.mac).await?;
        stream.flush().await?;
        Ok(())
    }
}
