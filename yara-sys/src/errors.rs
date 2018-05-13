use std::error;
use std::fmt;
use std::os::raw::c_int;

use ERROR_CALLBACK_ERROR;
use ERROR_CORRUPT_FILE;
use ERROR_COULD_NOT_ATTACH_TO_PROCESS;
use ERROR_COULD_NOT_MAP_FILE;
use ERROR_COULD_NOT_OPEN_FILE;
use ERROR_INSUFFICIENT_MEMORY;
use ERROR_INTERNAL_FATAL_ERROR;
use ERROR_INVALID_FILE;
use ERROR_SCAN_TIMEOUT;
use ERROR_SUCCESS;
use ERROR_SYNTAX_ERROR;
use ERROR_TOO_MANY_MATCHES;
use ERROR_UNSUPPORTED_FILE_VERSION;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Callback returned an error
    CallbackError,
    /// Rule file is corrupt
    CorruptFile,
    /// Could not attach to process
    CouldNotAttach,
    /// File could not be mapped into memory
    CouldNotMapFile,
    /// File could not be opened
    CouldNotOpenFile,
    /// Insufficient memory to complete the operation
    InsufficientMemory,
    /// Internal fatal error
    InternalFatalError,
    /// File is not a valid rules file
    InvalidFile,
    /// Timeouted during scan
    ScanTimeout,
    /// Syntax error in rule
    SyntaxError,
    /// Too many matches
    TooManyMatches,
    /// Rule file version is not supported
    UnsupportedFileVersion,
    /// Unknown Yara error
    Unknown(i32),
}

impl Error {
    pub fn from_code(code: c_int) -> Result<(), Error> {
        use self::Error::*;

        if code as u32 == ERROR_SUCCESS {
            return Ok(());
        }

        Err(match code as u32 {
            ERROR_CALLBACK_ERROR => CallbackError,
            ERROR_CORRUPT_FILE => CorruptFile,
            ERROR_COULD_NOT_ATTACH_TO_PROCESS => CouldNotAttach,
            ERROR_COULD_NOT_MAP_FILE => CouldNotMapFile,
            ERROR_COULD_NOT_OPEN_FILE => CouldNotOpenFile,
            ERROR_INSUFFICIENT_MEMORY => InsufficientMemory,
            ERROR_INTERNAL_FATAL_ERROR => InternalFatalError,
            ERROR_INVALID_FILE => InvalidFile,
            ERROR_SCAN_TIMEOUT => ScanTimeout,
            ERROR_SYNTAX_ERROR => SyntaxError,
            ERROR_TOO_MANY_MATCHES => TooManyMatches,
            ERROR_UNSUPPORTED_FILE_VERSION => UnsupportedFileVersion,
            _ => Unknown(code),
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.clone().into())
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        self.clone().into()
    }
}

impl From<Error> for &'static str {
    fn from(error: Error) -> &'static str {
        use self::Error::*;

        match error {
            CallbackError => "Callback returned an error",
            CorruptFile => "Rule file is corrupt",
            CouldNotAttach => "Could not attach to process",
            CouldNotMapFile => "File could not be mapped into memory",
            CouldNotOpenFile => "File could not be opened",
            InsufficientMemory => "Insufficient memory to complete the operation",
            InternalFatalError => "Internal fatal error",
            InvalidFile => "File is not a valid rules file",
            ScanTimeout => "Timeouted during scan",
            SyntaxError => "Syntax error in rule",
            TooManyMatches => "Too many matches",
            UnsupportedFileVersion => "Rule file version is not supported",
            Unknown(_) => "Unknown Yara error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_from_code() {
        use super::Error::*;

        assert_eq!(Ok(()), Error::from_code(ERROR_SUCCESS as i32));
        assert_eq!(
            Err(InsufficientMemory),
            Error::from_code(ERROR_INSUFFICIENT_MEMORY as i32)
        );
        assert_eq!(
            Err(ScanTimeout),
            Error::from_code(ERROR_SCAN_TIMEOUT as i32)
        );
    }

    #[test]
    fn test_to_string() {
        use std::error::Error as StdError;
        assert_eq!("Callback returned an error", Error::CallbackError.to_string());
        assert_eq!("Callback returned an error", Error::CallbackError.description());
    }
}
