pub mod matches;
pub mod string;

mod compiler;
mod rules;
mod scan;

pub use self::compiler::*;
pub use self::rules::*;
pub use self::scan::*;

use std::sync::Mutex;

use yara_sys;

use errors::*;

lazy_static! {
    static ref INIT_MUTEX: Mutex<()> = Mutex::new(());
}

/// Initialize the Yara library
///
/// Can be called multiple times without problems.
/// Is thread safe.
pub fn initialize() -> Result<(), YaraError> {
    let _guard = INIT_MUTEX.lock();
    let result = unsafe { yara_sys::yr_initialize() };

    yara_sys::Error::from_code(result).map_err(Into::into)
}

/// De-initialize the Yara library
///
/// Must not be called more time than [`initialize`].
/// Is thread safe.
pub fn finalize() -> Result<(), YaraError> {
    let _guard = INIT_MUTEX.lock();
    let result = unsafe { yara_sys::yr_finalize() };

    yara_sys::Error::from_code(result).map_err(Into::into)
}

/// Get the Yara thread id.
pub fn get_tidx() -> i32 {
    unsafe { yara_sys::yr_get_tidx() }
}
