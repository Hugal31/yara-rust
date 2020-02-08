use std::fmt;

pub use yara_sys::CompileErrorLevel;

use failure::{Backtrace, Context, Fail};

/// A wrapper around the kinds of errors that can happen in the library.
#[derive(Debug, Fail)]
pub enum Error {
    /// An IO error.
    #[fail(display = "{}", _0)]
    Io(#[cause] IoError),
    /// A general Yara error.
    ///
    /// See [`YaraError`] and [`yara_sys::Error`].
    #[fail(display = "{}", _0)]
    Yara(#[cause] YaraError),
    /// A rule compilation error.
    #[fail(display = "{}", _0)]
    Compile(#[cause] CompileErrors),
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

impl From<CompileErrors> for Error {
    fn from(error: CompileErrors) -> Self {
        Error::Compile(error)
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
    fn cause(&self) -> Option<&dyn Fail> {
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
    #[fail(display = "Error while opening scan file")]
    OpenScanFile,
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

/// The errors and warning returned during the rules compilation.
#[derive(Debug)]
pub struct CompileErrors {
    errors: Vec<CompileError>,
}

impl CompileErrors {
    pub fn new(errors: Vec<CompileError>) -> Self {
        CompileErrors { errors }
    }

    /// Iterate over the errors.
    pub fn iter(&self) -> impl Iterator<Item = &CompileError> {
        self.errors.iter()
    }
}

impl Fail for CompileErrors {
    /// Returns the first error.
    fn cause(&self) -> Option<&dyn Fail> {
        self.iter()
            .find(|e| e.level == yara_sys::CompileErrorLevel::Error)
            .map(|e| e as &dyn Fail)
    }
}

impl fmt::Display for CompileErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for error in &self.errors {
            writeln!(f, "{}", error)?;
        }

        Ok(())
    }
}

#[derive(Debug, Fail)]
pub struct CompileError {
    pub level: CompileErrorLevel,
    pub filename: Option<String>,
    pub line: usize,
    pub message: String,
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Compile {} ",
            match self.level {
                CompileErrorLevel::Error => "error",
                CompileErrorLevel::Warning => "warning",
            }
        )?;
        if let Some(filename) = &self.filename {
            write!(f, "in {} ", filename)?;
        }
        write!(f, "at line {}: {}", self.line, self.message)
    }
}
