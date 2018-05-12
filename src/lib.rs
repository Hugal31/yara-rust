#[macro_use]
extern crate failure;
extern crate yara_sys;

mod rules;

pub mod errors;

mod internals;

pub use errors::*;
pub use rules::*;

/// Yara library
///
/// # FFI
///
/// libyara asks to call `yr_initialize` before use the library.
/// Because yara keeps a count of how many times `yr_initialize` is used, it doesn't matter if this struct is constructed multiple times.
pub struct Yara();

impl Yara {
    pub fn create() -> Result<Yara, YaraError> {
        internals::initialize().map(|()| Yara())
    }

    // TODO Check if method is thread safe, and if "mut" is needed.
    pub fn new_compiler<'a>(&'a mut self) -> Result<Compiler<'a>, YaraError> {
        Compiler::<'a>::create()
    }
}

/// Finalize the Yara library
// TODO: What to do if yr_finalize return something else than ERROR_SUCCESS ?
impl Drop for Yara {
    fn drop(&mut self) {
        internals::finalize().expect("Expect correct Yara finalization");
    }
}

/// Yara compiler
pub struct Compiler<'a> {
    inner: &'a mut yara_sys::YR_COMPILER,
}

impl<'a> Compiler<'a> {
    pub(crate) fn create() -> Result<Compiler<'a>, YaraError> {
        internals::compiler_create().map(|compiler| Compiler { inner: compiler })
    }

    pub fn add_rule_str(&mut self, rule: &str) -> Result<(), CompilationError> {
        internals::compiler_add_string(self.inner, rule, None)
    }

    pub fn add_rule_str_with_namespace(
        &mut self,
        rule: &str,
        namespace: &str,
    ) -> Result<(), CompilationError> {
        internals::compiler_add_string(self.inner, rule, Some(namespace))
    }

    pub fn get_rules(self) -> Result<Rules<'a>, YaraError> {
        internals::compiler_get_rules(self.inner).map(|r| Rules::from(r))
    }
}

impl<'a> Drop for Compiler<'a> {
    fn drop(&mut self) {
        internals::compiler_destroy(self.inner);
    }
}
