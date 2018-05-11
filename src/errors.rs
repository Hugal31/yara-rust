use std::fmt;
use std::str::Utf8Error;

use failure::{Context, Backtrace, Fail};

use yara_sys::{ERROR_INSUFFICIENT_MEMORY, ERROR_SCAN_TIMEOUT, ERROR_SUCCESS};

#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        *self.inner.get_context()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

#[derive(Clone, Copy, Debug, Fail, Eq, PartialEq)]
pub enum ErrorKind {
    #[fail(display = "Utf8 error: {:?}", _0)]
    Utf8(#[cause] Utf8Error),
    #[fail(display = "{}", _0)]
    Yara(#[cause] YaraError),
}

impl From<Context<ErrorKind>> for Error {
    fn from(ctx: Context<ErrorKind>) -> Error {
        Error { inner: ctx }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error { inner: Context::new(kind) }
    }
}

pub type YaraError = YaraErrorKind;

impl From<YaraError> for Error {
    fn from(error: YaraError) -> Error {
        ErrorKind::Yara(error).into()
    }
}

#[derive(Clone, Copy, Debug, Fail, Eq, PartialEq)]
#[fail(display = "Error(s) during rule compilation.")]
pub struct CompilationError();

#[derive(Clone, Copy, Debug, Fail, Eq, PartialEq)]
pub enum YaraErrorKind {
    #[fail(display = "Insufficient memory to complete the operation.")]
    InsufficientMemory,
    #[fail(display = "Timeouted during scan.")]
    ScanTimeout,
    #[fail(display = "Unknown Yara error: {}", _0)]
    Unknown(u32),
}

impl YaraErrorKind {
    pub(crate) fn from_yara(code: i32) -> Result<(), YaraErrorKind> {
        let code = code as u32;
        use self::YaraErrorKind::*;

        match code {
            ERROR_SUCCESS => Ok(()),
            ERROR_INSUFFICIENT_MEMORY => Err(InsufficientMemory),
            ERROR_SCAN_TIMEOUT => Err(ScanTimeout),
            _ => Err(Unknown(code)),
        }
    }
}
