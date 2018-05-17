use std::fmt;

use failure::{Backtrace, Context, Fail};
use yara_sys;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "{}", _0)]
    Io(#[cause] IoError),
    #[fail(display = "{}", _0)]
    Yara(#[cause] YaraError),
}

impl From<IoError> for Error {
    fn from(error: IoError) -> Self {
        Error::Io(error)
    }
}

impl From<YaraError> for Error {
    fn from(error: YaraError) -> Self {
        Error::Yara(error)
    }
}

#[derive(Debug)]
pub struct IoError {
    inner: Context<IoErrorKind>,
}

impl IoError {
    pub fn kind(&self) -> &IoErrorKind {
        self.inner.get_context()
    }
}

impl From<IoErrorKind> for IoError {
    fn from(kind: IoErrorKind) -> Self {
        IoError {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<IoErrorKind>> for IoError {
    fn from(ctx: Context<IoErrorKind>) -> Self {
        IoError { inner: ctx }
    }
}

impl Fail for IoError {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Fail, Eq, PartialEq)]
pub enum IoErrorKind {
    #[fail(display = "Error while opening rules file")]
    OpenRulesFile,
}

#[derive(Clone, Copy, Debug, Fail, Eq, PartialEq)]
#[fail(display = "{}", kind)]
pub struct YaraError {
    pub kind: yara_sys::Error,
}

impl From<yara_sys::Error> for YaraError {
    fn from(error: yara_sys::Error) -> Self {
        YaraError { kind: error }
    }
}
