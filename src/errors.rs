use std::fmt;
use std::str::Utf8Error;

use failure::{Backtrace, Context, Fail};

use yara_sys::{ERROR_INSUFFICIENT_MEMORY, ERROR_SCAN_TIMEOUT, ERROR_SUCCESS};

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Utf8 error: {:?}", _0)]
    Utf8(#[cause] Utf8Error),
    #[fail(display = "{}", _0)]
    Yara(#[cause] YaraError),
}

impl From<Utf8Error> for Error {
    fn from(error: Utf8Error) -> Error {
        Error::Utf8(error).into()
    }
}

pub type YaraError = YaraErrorKind;

impl From<YaraError> for Error {
    fn from(error: YaraError) -> Error {
        Error::Yara(error).into()
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
