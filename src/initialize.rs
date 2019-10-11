use crate::{errors::*, internals};

/// Token to initialize the library.
///
/// # Implementation notes
///
/// libyara asks to call `yr_initialize` before use the library.
/// Because yara keeps a count of how many times `yr_initialize` is used,
/// it doesn't matter if this struct is constructed multiple times.
///
/// # TODO
///
/// Implement calls to yr_finalize_thread
#[derive(Debug)]
pub struct InitializationToken;

impl InitializationToken {
    /// Create and initialize the library.
    pub fn new() -> Result<InitializationToken, YaraError> {
        internals::initialize().map(|()| InitializationToken)
    }
}

/// Finalize the Yara library
impl Drop for InitializationToken {
    fn drop(&mut self) {
        internals::finalize().expect("Expect correct Yara finalization");
    }
}
