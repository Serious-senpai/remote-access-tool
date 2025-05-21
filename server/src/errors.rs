use std::error::Error;
use std::fmt;

use num::ToPrimitive;

#[derive(Debug)]
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

#[derive(Debug)]
pub struct IntegrityError {
    message: String,
}

impl Error for IntegrityError {}
impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl IntegrityError {
    pub fn from_message(message: String) -> Self {
        Self { message }
    }

    pub fn raw(message: &str) -> Self {
        Self::from_message(String::from(message))
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

#[derive(Debug)]
pub struct CastError<T>
where
    T: fmt::Debug + ToPrimitive,
{
    original: T,
}

impl<T> Error for CastError<T> where T: fmt::Debug + ToPrimitive {}
impl<T> fmt::Display for CastError<T>
where
    T: fmt::Debug + ToPrimitive,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Failed to cast value {:?}", self.original)
    }
}

impl<T> CastError<T>
where
    T: fmt::Debug + ToPrimitive,
{
    pub fn new(original: T) -> Self {
        Self { original }
    }
}
