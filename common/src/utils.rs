use std::error::Error;

use num::Zero;
use rsa::BigUint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Reads a string from the reader. The first 4 bytes are the length of the string,
pub async fn read_string<S>(reader: &mut S) -> Result<Vec<u8>, Box<dyn Error>>
where
    S: AsyncReadExt + Unpin,
{
    let length = reader.read_u32().await? as usize;
    let mut buffer = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut buffer).await?;
    }

    Ok(buffer)
}

/// Writes a string to the writer. The first 4 bytes are the length of the string.
pub async fn write_string<S>(writer: &mut S, string: &[u8]) -> Result<(), Box<dyn Error>>
where
    S: AsyncWriteExt + Unpin,
{
    writer.write_u32(string.len() as u32).await?;
    writer.write_all(string).await?;
    Ok(())
}

pub async fn write_string_vec(writer: &mut Vec<u8>, string: &[u8]) {
    write_string(writer, string)
        .await
        .expect("Writing to a vector should never fail")
}

pub async fn read_biguint<S>(reader: &mut S) -> Result<BigUint, Box<dyn Error>>
where
    S: AsyncReadExt + Unpin,
{
    let repr = read_string(reader).await?;
    if repr.is_empty() {
        return Ok(BigUint::zero());
    }

    Ok(BigUint::from_bytes_be(&repr))
}

pub async fn write_biguint<S>(writer: &mut S, biguint: &BigUint) -> Result<(), Box<dyn Error>>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buffer = biguint.to_bytes_be();
    if let Some(&first) = buffer.first() {
        if first & 0x80 != 0 {
            buffer.insert(0, 0);
        }
    }

    write_string(writer, &buffer).await?;
    Ok(())
}

pub async fn write_biguint_vec(writer: &mut Vec<u8>, biguint: &BigUint) {
    write_biguint(writer, biguint)
        .await
        .expect("Writing to a vector should never fail")
}
