
use std::fmt::Formatter;
use std::{
    error::Error as StdError,
    fmt::{self, Display},
};

pub type Result<T> = std::result::Result<T, Error>;

type StdThreadError = dyn StdError + Send + Sync;

pub struct Error {
    repr: Repr,
}

impl StdError for Error {}

#[derive(Debug)]
enum Repr {
    Simple(ErrorKind),
    Custom(Box<Custom>),
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorKind {
    
    InvalidPacket,

    InvalidHeader,

    InvalidPayload,

    InvalidSURB,

    InvalidRouting,
}

impl ErrorKind {
    pub(crate) fn as_str(&self) -> &'static str { panic!("STUB: not implemented") }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self { panic!("STUB: not implemented") }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), fmt::Error> { panic!("STUB: not implemented") }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { panic!("STUB: not implemented") }
}

#[derive(Debug)]
struct Custom {
    kind: ErrorKind,
    error: Box<StdThreadError>,
}

impl Error {
    pub fn new<E>(kind: ErrorKind, error: E) -> Self
    where
        E: Into<Box<StdThreadError>>,
    { panic!("STUB: not implemented") }

    pub fn kind(&self) -> ErrorKind { panic!("STUB: not implemented") }
}
