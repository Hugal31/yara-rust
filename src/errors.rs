use yara_sys::{ERROR_INSUFFICIENT_MEMORY, ERROR_SCAN_TIMEOUT, ERROR_SUCCESS};

pub type YaraError = YaraErrorKind;

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
