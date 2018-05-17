#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate yara_sys;

mod internals;
mod rules;

pub mod errors;

pub use errors::*;
pub use rules::*;

use std::fs::File;
use std::path::Path;

use failure::ResultExt;

/// Yara library
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

/// Yara rules compiler
pub struct Compiler<'a> {
    inner: &'a mut yara_sys::YR_COMPILER,
}

impl<'a> Compiler<'a> {
    pub(crate) fn create() -> Result<Compiler<'a>, YaraError> {
        internals::compiler_create().map(|compiler| Compiler { inner: compiler })
    }

    /// Add rule definitions from a file.
    pub fn add_rules_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Error> {
        File::open(path.as_ref())
            .context(IoErrorKind::OpenRulesFile)
            .map_err(|e| Into::<IoError>::into(e).into())
            .and_then(|file| {
                internals::compiler_add_file(self.inner, &file, path, None).map_err(Into::into)
            })
    }

    /// Add rule definitions from a file within a namespace.
    pub fn add_rules_file_with_namespace<P: AsRef<Path>>(
        &mut self,
        path: P,
        namespace: &str,
    ) -> Result<(), Error> {
        File::open(path.as_ref())
            .context(IoErrorKind::OpenRulesFile)
            .map_err(|e| Into::<IoError>::into(e).into())
            .and_then(|file| {
                internals::compiler_add_file(self.inner, &file, path, Some(namespace))
                    .map_err(Into::into)
            })
    }

    /// Add rule definitions from a string.
    pub fn add_rules_str(&mut self, rule: &str) -> Result<(), YaraError> {
        internals::compiler_add_string(self.inner, rule, None)
    }

    /// Add rule definition from a string within a namespace.
    pub fn add_rule_str_with_namespace(
        &mut self,
        rule: &str,
        namespace: &str,
    ) -> Result<(), YaraError> {
        internals::compiler_add_string(self.inner, rule, Some(namespace))
    }

    /// Compile the rules.
    pub fn compile_rules(self) -> Result<Rules<'a>, YaraError> {
        internals::compiler_get_rules(self.inner).map(Rules::from)
    }
}

impl<'a> Drop for Compiler<'a> {
    fn drop(&mut self) {
        internals::compiler_destroy(self.inner);
    }
}
