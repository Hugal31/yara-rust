mod compiler;
mod rules;
mod scan;

pub use self::compiler::*;
pub use self::rules::*;
pub use self::scan::*;

use yara_sys;

use errors::*;

pub type Compiler = yara_sys::YR_COMPILER;
pub type Rule = yara_sys::YR_RULE;
pub type Rules = yara_sys::YR_RULES;

/// Initialize the Yara library
///
/// Can be called multiple times without problems
pub fn initialize() -> Result<(), YaraError> {
    let result = unsafe { yara_sys::yr_initialize() };

    YaraErrorKind::from_yara(result)
}

/// De-initialize the Yara library
///
/// Must not be called more time than [`initialize`].
pub fn finalize() -> Result<(), YaraError> {
    let result = unsafe { yara_sys::yr_finalize() };

    YaraErrorKind::from_yara(result)
}

pub fn get_tidx() -> i32 {
    unsafe { yara_sys::yr_get_tidx() }
}
