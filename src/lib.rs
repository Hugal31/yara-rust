#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate yara_sys;

mod compiler;
mod internals;
mod matches;
mod rules;
mod string;

pub mod errors;

pub use compiler::Compiler;
pub use errors::*;
pub use matches::Match;
pub use rules::*;
pub use string::YrString;

/// Yara library.
/// Necessary to use the features of this crate.
///
/// # Implementation notes
///
/// libyara asks to call `yr_initialize` before use the library.
/// Because yara keeps a count of how many times `yr_initialize` is used,
/// it doesn't matter if this struct is constructed multiple times.
pub struct Yara {
    _secret: (),
}

impl Yara {
    /// Create and initialize the library.
    pub fn create() -> Result<Yara, YaraError> {
        internals::initialize().map(|()| Yara { _secret: () })
    }

    /// Create a new compiler.
    // TODO Check if method is thread safe, and if "mut" is needed.
    pub fn new_compiler<'a>(&'a mut self) -> Result<Compiler<'a>, YaraError> {
        Compiler::<'a>::create()
    }

    /// Load rules from a pre-compiled rules file.
    // TODO Check if method is thread safe, and if "mut" is needed.
    // TODO Take AsRef<Path> ?
    pub fn load_rules<'a>(&'a mut self, filename: &str) -> Result<Rules<'a>, YaraError> {
        internals::rules_load(filename).map(Rules::from)
    }
}

/// Finalize the Yara library
// TODO: What to do if yr_finalize return something else than ERROR_SUCCESS ?
impl Drop for Yara {
    fn drop(&mut self) {
        internals::finalize().expect("Expect correct Yara finalization");
    }
}
