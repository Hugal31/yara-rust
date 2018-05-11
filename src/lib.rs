#[macro_use]
extern crate failure;
extern crate yara_sys;

pub mod errors;

mod internals;

pub use errors::*;

use std::marker;

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
// TODO Check what is done if multiple create
pub struct Compiler<'a> {
    inner: *mut internals::Compiler,
    _marker: marker::PhantomData<&'a ()>,
}

impl<'a> Compiler<'a> {
    pub(crate) fn create() -> Result<Compiler<'a>, YaraError> {
        internals::compiler_create().map(|ptr| Compiler {
            inner: ptr,
            _marker: marker::PhantomData::default(),
        })
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
        internals::compiler_get_rules(self.inner).map(|r| Rules::<'a>::from(r))
    }
}

impl<'a> Drop for Compiler<'a> {
    fn drop(&mut self) {
        internals::compiler_destroy(self.inner);
    }
}

pub struct Rules<'a> {
    inner: *mut internals::Rules,
    _marker: marker::PhantomData<&'a ()>,
}

impl<'a> Rules<'a> {
    pub(crate) fn from(rules: *mut internals::Rules) -> Rules<'a> {
        Rules {
            inner: rules,
            _marker: marker::PhantomData::default(),
        }
    }

    /// Scan memory
    ///
    /// The timeout is in seconds
    pub fn scan_mem(&mut self, mem: &[u8], timeout: u16) -> Result<(), YaraError> {
        internals::rules_scan_mem(self.inner, mem, timeout as i32)
    }

    /// Save the rule to a file
    // TODO Take AsRef<Path> ?
    pub fn save(&mut self, filename: &str) -> Result<(), YaraError> {
        internals::rules_save(self.inner, filename)
    }
}

impl<'a> Drop for Rules<'a> {
    fn drop(&mut self) {
        internals::rules_destroy(self.inner);
    }
}
