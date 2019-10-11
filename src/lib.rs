mod compiler;
mod initialize;
mod internals;
mod matches;
mod rules;
mod string;

pub mod errors;

use crate::initialize::InitializationToken;

pub use crate::compiler::Compiler;
pub use crate::errors::*;
pub use crate::matches::Match;
pub use crate::rules::*;
pub use crate::string::YrString;

/// Yara library.
///
/// Act as an initialization token to keep the library initialized.
/// Not mandatory, but can reduce initialization overhead when creating and destroying Yara objects:
/// The library is initialized each time a new object is created, unless it is already initialized.
/// When the last yara object is destroyed,
///
/// # Example
/// ```no_run
/// # use yara::{Compiler, Rules, Yara};
/// {  // Initialize the library...
///     let compiler = Compiler::new().unwrap();
///     // ...
/// } // De-initialize the library...
///
/// {  // Initialize the again library...
///     let compiler = Rules::load_from_file("compiled_rules.yr").unwrap();
///     // ...
/// } // De-initialize the library...
///
/// let _yara = Yara::new().expect("Should initialize");
/// // Go on, the library will be initialized until the end of the scope.
/// ```
///
/// # Implementation notes
///
/// libyara asks to call `yr_initialize` before use the library.
/// Because yara keeps a count of how many times `yr_initialize` is used,
/// it doesn't matter if this struct is constructed multiple times.
pub struct Yara {
    _token: InitializationToken,
}

impl Yara {
    /// Create and initialize the library.
    pub fn new() -> Result<Yara, YaraError> {
        InitializationToken::new().map(|token| Yara { _token: token })
    }

    /// Create and initialize the library.
    #[deprecated = "Use new"]
    pub fn create() -> Result<Yara, YaraError> {
        Self::new()
    }

    /// Create a new compiler.
    #[deprecated = "Use Compiler::new"]
    pub fn new_compiler(&self) -> Result<Compiler, YaraError> {
        Compiler::new()
    }

    /// Load rules from a pre-compiled rules file.
    // TODO Take AsRef<Path> ?
    #[deprecated = "Use Rules::load_from_file"]
    pub fn load_rules(&self, filename: &str) -> Result<Rules, YaraError> {
        Rules::load_from_file(filename)
    }
}
