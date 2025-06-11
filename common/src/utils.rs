use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;
use std::str::FromStr;

use rsa::BigUint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;

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

pub async fn write_address<S>(
    writer: &mut S,
    address: &SocketAddr,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: AsyncWriteExt + Unpin,
{
    write_string(writer, address.to_string().as_bytes()).await?;
    Ok(())
}

pub async fn read_address<S>(reader: &mut S) -> Result<SocketAddr, Box<dyn Error + Send + Sync>>
where
    S: AsyncReadExt + Unpin,
{
    let addr_str = String::from_utf8(read_string(reader).await?)?;
    Ok(SocketAddr::from_str(&addr_str)?)
}

pub struct ConsoleTable<const COL: usize> {
    _rows: Vec<[String; COL]>,
}

impl<const COL: usize> ConsoleTable<COL> {
    pub fn new(headers: [String; COL]) -> Self {
        Self {
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
        for (i, w) in width.iter().enumerate() {
            if i > 0 {
                print!("-+-");
            }
            print!("{:-<width$}", "", width = w);
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

pub fn format_time(mut seconds: u64) -> String {
    let days = seconds / 86400;
    seconds -= 86400 * days;

    let hours = seconds / 3600;
    seconds -= 3600 * hours;

    let minutes = seconds / 60;
    seconds -= 60 * minutes;

    let mut tokens = vec![];
    if days > 0 {
        tokens.push(format!("{}d", days));
    }
    if hours > 0 {
        tokens.push(format!("{}h", hours));
    }
    if minutes > 0 {
        tokens.push(format!("{}m", minutes));
    }
    if seconds > 0 || tokens.is_empty() {
        tokens.push(format!("{}s", seconds));
    }

    tokens.join(" ")
}

pub async fn wait_for<T, F, R>(receiver: &mut broadcast::Receiver<T>, execute: impl Fn(T) -> F) -> R
where
    T: Clone,
    F: Future<Output = Option<R>>,
{
    loop {
        if let Ok(packet) = receiver.recv().await {
            if let Some(result) = execute(packet).await {
                break result;
            }
        }
    }
}

pub fn strip(text: String, max_length: usize) -> String {
    if text.len() <= max_length {
        text
    } else {
        format!("{}...", &text[..max_length - 3])
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use tokio::io::{BufReader, BufWriter};

    use super::*;

    #[tokio::test]
    async fn test_read_write_string() {
        let original = b"Hello, World!";
        let mut buffer = vec![];

        {
            let mut writer = BufWriter::new(&mut buffer);
            write_string(&mut writer, original).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(&buffer[..]);
        let result = read_string(&mut reader).await.unwrap();

        assert_eq!(result, original);
    }

    #[tokio::test]
    async fn test_read_write_empty_string() {
        let original = b"";
        let mut buffer = vec![];

        {
            let mut writer = BufWriter::new(&mut buffer);
            write_string(&mut writer, original).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(&buffer[..]);
        let result = read_string(&mut reader).await.unwrap();

        assert_eq!(result, original);
    }

    #[tokio::test]
    async fn test_write_string_vec() {
        let original = b"Test data";
        let mut buffer = vec![];

        write_string_vec(&mut buffer, original).await;

        let mut reader = BufReader::new(&buffer[..]);
        let result = read_string(&mut reader).await.unwrap();

        assert_eq!(result, original);
    }

    #[tokio::test]
    async fn test_read_write_biguint() {
        let original = BigUint::from(12345678901234567890u64);
        let mut buffer = vec![];

        {
            let mut writer = BufWriter::new(&mut buffer);
            write_biguint(&mut writer, &original).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(&buffer[..]);
        let result = read_biguint(&mut reader).await.unwrap();

        assert_eq!(result, original);
    }

    #[tokio::test]
    async fn test_read_write_zero_biguint() {
        let original = BigUint::new(vec![]);
        let mut buffer = vec![];

        {
            let mut writer = BufWriter::new(&mut buffer);
            write_biguint(&mut writer, &original).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(&buffer[..]);
        let result = read_biguint(&mut reader).await.unwrap();

        assert_eq!(result, original);
    }

    #[tokio::test]
    async fn test_write_biguint_vec() {
        let original = BigUint::from(42u32);
        let mut buffer = vec![];

        write_biguint_vec(&mut buffer, &original).await;

        let mut reader = BufReader::new(&buffer[..]);
        let result = read_biguint(&mut reader).await.unwrap();

        assert_eq!(result, original);
    }

    #[tokio::test]
    async fn test_read_write_ipv4_address() {
        let original = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let mut buffer = vec![];

        {
            let mut writer = BufWriter::new(&mut buffer);
            write_address(&mut writer, &original).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(&buffer[..]);
        let result = read_address(&mut reader).await.unwrap();

        assert_eq!(result, original);
    }

    #[tokio::test]
    async fn test_read_write_ipv6_address() {
        let original = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 3000);
        let mut buffer = vec![];

        {
            let mut writer = BufWriter::new(&mut buffer);
            write_address(&mut writer, &original).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut reader = BufReader::new(&buffer[..]);
        let result = read_address(&mut reader).await.unwrap();

        assert_eq!(result, original);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0.00 B");
        assert_eq!(format_bytes(512), "512.00 B");
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(1536), "1.50 KiB");
        assert_eq!(format_bytes(1048576), "1.00 MiB");
        assert_eq!(format_bytes(1073741824), "1.00 GiB");
        assert_eq!(format_bytes(1610612736), "1.50 GiB");
    }

    #[test]
    fn test_format_time() {
        assert_eq!(format_time(0), "0s");
        assert_eq!(format_time(30), "30s");
        assert_eq!(format_time(60), "1m");
        assert_eq!(format_time(90), "1m 30s");
        assert_eq!(format_time(3600), "1h");
        assert_eq!(format_time(3661), "1h 1m 1s");
        assert_eq!(format_time(86400), "1d");
        assert_eq!(format_time(90061), "1d 1h 1m 1s");
    }

    #[test]
    fn test_strip() {
        assert_eq!(strip("hello".to_string(), 10), "hello");
        assert_eq!(strip("hello world".to_string(), 8), "hello...");
        assert_eq!(strip("test".to_string(), 4), "test");
        assert_eq!(strip("testing".to_string(), 6), "tes...");
    }

    #[test]
    fn test_console_table() {
        let mut table = ConsoleTable::new(["Name".to_string(), "Age".to_string()]);
        table.add_row(["Alice".to_string(), "30".to_string()]);
        table.add_row(["Bob".to_string(), "25".to_string()]);

        // Just test that print doesn't panic
        table.print();
    }

    #[tokio::test]
    async fn test_wait_for() {
        let (tx, mut rx) = broadcast::channel(10);

        // Spawn a task to send values
        tokio::spawn(async move {
            tx.send(1).unwrap();
            tx.send(2).unwrap();
            tx.send(3).unwrap();
        });

        let result = wait_for(&mut rx, |value| async move {
            if value == 2 {
                Some(value * 10)
            } else {
                None
            }
        })
        .await;

        assert_eq!(result, 20);
    }
}
