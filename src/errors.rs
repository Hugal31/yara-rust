use std::fmt;

pub use yara_sys::CompileErrorLevel;

use std::error::Error as StdError;

use thiserror::Error as ThisError;

/// A wrapper around the kinds of errors that can happen in the library.
#[derive(Debug, ThisError)]
pub enum Error {
    /// An IO error.
    #[error("{0}")]
    Io(#[from] IoError),
    /// A general Yara error.
    ///
    /// See [`YaraError`] and [`yara_sys::Error`].
    #[error("{0}")]
    Yara(#[from] YaraError),
    /// A rule compilation error.
    #[error("{0}")]
    Compile(#[from] CompileErrors),
}

#[derive(Debug, ThisError)]
#[error("{context}: {inner}")]
pub struct IoError {
    context: IoErrorKind,
    #[source]
    inner: std::io::Error,
}

impl IoError {
    pub fn new(inner: std::io::Error, context: IoErrorKind) -> Self {
        IoError { context, inner }
    }

    pub fn kind(&self) -> &IoErrorKind {
        &self.context
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
pub enum IoErrorKind {
    #[error("Error while opening scan file")]
    OpenScanFile,
    #[error("Error while opening rules file")]
    OpenRulesFile,
    #[error("Error while reading rules stream")]
    ReadingRules,
    #[error("Error while writing rules stream")]
    WritingRules,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
#[error("{kind}")]
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

impl StdError for CompileErrors {
    /// Returns the first compile error.
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.iter()
            .find(|e| e.level == yara_sys::CompileErrorLevel::Error)
            .map(|e| e as &dyn StdError)
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

#[derive(Debug, ThisError)]
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
