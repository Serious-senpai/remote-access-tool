use std::error::Error;

use rsa::BigUint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Reads a string from the reader. The first 4 bytes are the length of the string,
pub async fn read_string<S>(reader: &mut S) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>
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
pub async fn write_string<S>(
    writer: &mut S,
    string: &[u8],
) -> Result<(), Box<dyn Error + Send + Sync>>
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

pub async fn read_biguint<S>(reader: &mut S) -> Result<BigUint, Box<dyn Error + Send + Sync>>
where
    S: AsyncReadExt + Unpin,
{
    let repr = read_string(reader).await?;
    if repr.is_empty() {
        return Ok(BigUint::new(vec![]));
    }

    Ok(BigUint::from_bytes_be(&repr))
}

pub async fn write_biguint<S>(
    writer: &mut S,
    biguint: &BigUint,
) -> Result<(), Box<dyn Error + Send + Sync>>
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

pub struct ConsoleTable<const COL: usize> {
    _rows: Vec<[String; COL]>,
}

impl<const COL: usize> ConsoleTable<COL> {
    pub fn new(headers: [String; COL]) -> Self {
        ConsoleTable {
            _rows: vec![headers],
        }
    }

    pub fn add_row(&mut self, row: [String; COL]) {
        self._rows.push(row);
    }

    pub fn print(&self) {
        let mut width = [0; COL];
        for row in &self._rows {
            for (i, cell) in row.iter().enumerate() {
                width[i] = width[i].max(cell.len());
            }
        }

        fn print_row(row: &[String], width: &[usize]) {
            for i in 0..row.len() {
                if i > 0 {
                    print!(" | ");
                }
                print!("{:width$}", row[i], width = width[i]);
            }
            println!();
        }

        print_row(&self._rows[0], &width);
        for i in 0..COL {
            if i > 0 {
                print!("-+-");
            }
            print!("{:-<width$}", "", width = width[i]);
        }
        println!();

        for row in &self._rows[1..] {
            print_row(row, &width);
        }
    }
}

/// Unpack the computation result, or log the error and immediately return the current function.
#[macro_export]
macro_rules! log_error {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                error!("[{}:{}] {}", file!(), line!(), e);
                return Err(e)?;
            }
        }
    };
}

pub fn format_bytes(bytes: u64) -> String {
    let mut value = bytes as f64;
    let mut unit = "B";

    if value >= 1024.0 {
        value /= 1024.0;
        unit = "KiB";
    }
    if value >= 1024.0 {
        value /= 1024.0;
        unit = "MiB";
    }
    if value >= 1024.0 {
        value /= 1024.0;
        unit = "GiB";
    }

    format!("{:.2} {}", value, unit)
}
