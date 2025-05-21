use std::error::Error;

use tokio::io::{AsyncReadExt, BufReader};

use crate::errors::UnexpectedPacket;
use crate::packets::SSHPacket;

pub trait PayloadFormat {
    const OPCODE: u8;

    async fn from_stream<S>(stream: &mut S) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
        S: AsyncReadExt + Unpin;

    async fn from_payload(payload: &[u8]) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let mut reader = BufReader::new(payload);
        Self::from_stream(&mut reader).await
    }

    async fn from_packet(packet: &SSHPacket) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        Self::from_payload(&packet.payload).await
    }

    fn check_opcode(opcode: u8) -> Result<(), UnexpectedPacket> {
        if opcode != Self::OPCODE {
            Err(UnexpectedPacket::new(Self::OPCODE, opcode))
        } else {
            Ok(())
        }
    }

    async fn to_stream<S>(&self, stream: &mut S) -> Result<(), Box<dyn Error>>
    where
        Self: Sized,
        S: tokio::io::AsyncWriteExt + Unpin;

    async fn to_payload(&self) -> Result<Vec<u8>, Box<dyn Error>>
    where
        Self: Sized,
    {
        let mut writer = vec![];
        self.to_stream(&mut writer).await?;
        Ok(writer)
    }

    async fn to_packet(&self) -> Result<SSHPacket, Box<dyn Error>>
    where
        Self: Sized,
    {
        let payload = self.to_payload().await?;
        Ok(SSHPacket::from_payload(payload))
    }
}
