use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct RuntimeError<T>
where
    T: fmt::Display,
{
    message: T,
}

impl<T> Error for RuntimeError<T> where T: fmt::Debug + fmt::Display {}
impl<T> fmt::Display for RuntimeError<T>
where
    T: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl<T> RuntimeError<T>
where
    T: fmt::Display,
{
    pub fn new(message: T) -> Self {
        Self { message }
    }
}

impl RuntimeError<String> {
    pub fn from_errors(errors: &[Box<dyn Error + Send + Sync>]) -> Self {
        let message = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        Self::new(message)
    }
}

#[derive(Debug)]
pub struct UnexpectedPacket {
    expected: u8,
    actual: u8,
}

impl Error for UnexpectedPacket {}
impl fmt::Display for UnexpectedPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Expected packet {}, got {}", self.expected, self.actual)
    }
}

impl UnexpectedPacket {
    pub fn new(expected: u8, actual: u8) -> Self {
        Self { expected, actual }
    }
}
