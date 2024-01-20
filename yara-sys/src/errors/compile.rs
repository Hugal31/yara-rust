use crate::YARA_ERROR_LEVEL_ERROR;
use crate::YARA_ERROR_LEVEL_WARNING;

/// The level of an error while parsing a rule file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompileErrorLevel {
    Error,
    Warning,
}

impl CompileErrorLevel {
    /// Convert from an i32 error code
    ///
    /// # Panics
    ///
    /// Panics if the code is not a valid value
    pub fn from_code(code: i32) -> CompileErrorLevel {
        match code as u32 {
            YARA_ERROR_LEVEL_ERROR => CompileErrorLevel::Error,
            YARA_ERROR_LEVEL_WARNING => CompileErrorLevel::Warning,
            _ => panic!(
                "Should be {} or {}",
                YARA_ERROR_LEVEL_ERROR, YARA_ERROR_LEVEL_WARNING
            ),
        }
    }

    /// Convert from an i32 error code.
    ///
    /// Returns `Err` if the code is not a valide value.
    pub fn try_from_code(code: i32) -> Result<CompileErrorLevel, i32> {
        match code as u32 {
            YARA_ERROR_LEVEL_ERROR => Ok(CompileErrorLevel::Error),
            YARA_ERROR_LEVEL_WARNING => Ok(CompileErrorLevel::Warning),
            _ => Err(code),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_code() {
        assert_eq!(
            CompileErrorLevel::Error,
            CompileErrorLevel::from_code(YARA_ERROR_LEVEL_ERROR as i32)
        );
        assert_eq!(
            CompileErrorLevel::Warning,
            CompileErrorLevel::from_code(YARA_ERROR_LEVEL_WARNING as i32)
        );
    }

    #[test]
    #[should_panic]
    fn test_from_code_panic() {
        CompileErrorLevel::from_code(64);
    }

    #[test]
    fn test_try_from_code() {
        assert_eq!(
            Ok(CompileErrorLevel::Error),
            CompileErrorLevel::try_from_code(YARA_ERROR_LEVEL_ERROR as i32)
        );
        assert_eq!(
            Ok(CompileErrorLevel::Warning),
            CompileErrorLevel::try_from_code(YARA_ERROR_LEVEL_WARNING as i32)
        );
        assert_eq!(Err(42), CompileErrorLevel::try_from_code(42));
    }
}
