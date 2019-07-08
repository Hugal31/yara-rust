use std::fs::File;
use std::marker::PhantomData;
use std::path::Path;

use failure::ResultExt;
use yara_sys;

use crate::errors::*;
use crate::internals;
use crate::Rules;

/// Yara rules compiler
pub struct Compiler<'c, 'y: 'c> {
    inner: &'c mut yara_sys::YR_COMPILER,
    _marker: PhantomData<&'y ()>,
}

impl<'c, 'y: 'c> Compiler<'c, 'y> {
    pub(crate) fn create() -> Result<Self, YaraError> {
        internals::compiler_create().map(|compiler| Compiler {
            inner: compiler,
            _marker: PhantomData,
        })
    }

    /// Add rule definitions from a file.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use yara::Yara;
    /// let mut yara = Yara::create().unwrap();
    /// let mut compiler = yara.new_compiler().unwrap();
    /// compiler.add_rules_file("rules.txt").expect("Should load rules");
    /// ```
    pub fn add_rules_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Error> {
        File::open(path.as_ref())
            .context(IoErrorKind::OpenRulesFile)
            .map_err(|e| Into::<IoError>::into(e).into())
            .and_then(|file| internals::compiler_add_file(self.inner, &file, path, None))
    }

    /// Add rule definitions from a file within a namespace.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use yara::Yara;
    /// let mut yara = Yara::create().unwrap();
    /// let mut compiler = yara.new_compiler().unwrap();
    /// compiler.add_rules_file_with_namespace("CVE-2010-1297.yar", "flash").expect("Should load rules");
    /// ```
    pub fn add_rules_file_with_namespace<P: AsRef<Path>>(
        &mut self,
        path: P,
        namespace: &str,
    ) -> Result<(), Error> {
        File::open(path.as_ref())
            .context(IoErrorKind::OpenRulesFile)
            .map_err(|e| Into::<IoError>::into(e).into())
            .and_then(|file| internals::compiler_add_file(self.inner, &file, path, Some(namespace)))
    }

    /// Add rule definitions from a string.
    ///
    /// # Example
    ///
    /// ```
    /// # use yara::Yara;
    /// let mut yara = Yara::create().unwrap();
    /// let mut compiler = yara.new_compiler().unwrap();
    /// compiler.add_rules_str("rule is_empty {
    ///   condition:
    ///     filesize == 0
    /// }").expect("Should compile rule");
    /// ```
    pub fn add_rules_str(&mut self, rule: &str) -> Result<(), Error> {
        internals::compiler_add_string(self.inner, rule, None)
    }

    /// Add rule definition from a string within a namespace.
    ///
    /// # Example
    ///
    /// ```
    /// # use yara::Yara;
    /// let mut yara = Yara::create().unwrap();
    /// let mut compiler = yara.new_compiler().unwrap();
    /// compiler.add_rules_str_with_namespace("rule is_empty {
    ///   condition:
    ///     filesize == 0
    /// }", "misc").expect("Should compile rule");
    /// ```
    pub fn add_rules_str_with_namespace(
        &mut self,
        rule: &str,
        namespace: &str,
    ) -> Result<(), Error> {
        internals::compiler_add_string(self.inner, rule, Some(namespace))
    }

    /// Compile the rules.
    ///
    /// # Implementation notes
    ///
    /// It is safe to destroy the compiler after, because the rules do not depends on the compiler.
    /// In addition, we must hide the compiler from the user because it can be used only once.
    pub fn compile_rules(self) -> Result<Rules<'y>, YaraError> {
        internals::compiler_get_rules(self.inner).map(Rules::from)
    }
}

impl<'c, 'y: 'c> Drop for Compiler<'c, 'y> {
    fn drop(&mut self) {
        internals::compiler_destroy(self.inner);
    }
}
