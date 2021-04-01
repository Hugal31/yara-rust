use std::convert::TryFrom as _;
use std::ffi::CStr;
use std::fs::File;
use std::path::Path;

use crate::errors::*;
use crate::initialize::InitializationToken;
use crate::internals;
use crate::Rules;

/// Yara rules compiler
pub struct Compiler {
    inner: *mut yara_sys::YR_COMPILER,
    _token: InitializationToken,
}

impl Compiler {
    /// Create a new compiler.
    pub fn new() -> Result<Self, YaraError> {
        let token = InitializationToken::new()?;

        internals::compiler_create().map(|inner| Compiler {
            inner,
            _token: token,
        })
    }

    /// Add rules definitions from a file.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use yara::Compiler;
    /// let mut compiler = Compiler::new()?;
    /// compiler.add_rules_file("rules.txt")?;
    /// # Ok::<(), yara::Error>(())
    /// ```
    pub fn add_rules_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Error> {
        File::open(path.as_ref())
            .map_err(|e| IoError::new(e, IoErrorKind::OpenRulesFile).into())
            .and_then(|file| internals::compiler_add_file(self.inner, &file, path, None))
    }

    /// Add rule definitions from a file within a namespace.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use yara::Compiler;
    /// let mut compiler = Compiler::new().unwrap();
    /// let rules = compiler.add_rules_file_with_namespace("CVE-2010-1297.yar", "flash")?;
    /// # Ok::<(), yara::Error>(())
    /// ```
    pub fn add_rules_file_with_namespace<P: AsRef<Path>>(
        &mut self,
        path: P,
        namespace: &str,
    ) -> Result<(), Error> {
        File::open(path.as_ref())
            .map_err(|e| IoError::new(e, IoErrorKind::OpenRulesFile).into())
            .and_then(|file| internals::compiler_add_file(self.inner, &file, path, Some(namespace)))
    }

    /// Add rule definitions from a string.
    ///
    /// # Example
    ///
    /// ```
    /// # use yara::Compiler;
    /// let mut compiler = Compiler::new()?;
    /// let rules = compiler.add_rules_str("rule is_empty {
    ///   condition:
    ///     filesize == 0
    /// }")?;
    /// # Ok::<(), yara::Error>(())
    /// ```
    pub fn add_rules_str(&mut self, rule: &str) -> Result<(), Error> {
        internals::compiler_add_string(self.inner, rule, None)
    }

    /// Add rule definition from a string within a namespace.
    ///
    /// # Example
    ///
    /// ```
    /// # use yara::Compiler;
    /// let mut compiler = Compiler::new()?;
    /// compiler.add_rules_str_with_namespace("rule is_empty {
    ///   condition:
    ///     filesize == 0
    /// }", "misc")?;
    /// # Ok::<(), yara::Error>(())
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
    /// Consume the compiler.
    ///
    /// # Implementation notes
    ///
    /// It is safe to destroy the compiler after, because the rules do not depends on the compiler.
    /// In addition, we must hide the compiler from the user because it can be used only once.
    pub fn compile_rules(self) -> Result<Rules, YaraError> {
        internals::compiler_get_rules(self.inner).and_then(Rules::try_from)
    }

    /// Add a variable to the compiler.
    ///
    /// Valid types are bool, i64, f64, str and cstr.
    ///
    /// Note: You must define all the external variables before adding rules to compile.
    ///
    /// # Example
    ///
    /// ```
    /// # use yara::Compiler;
    /// let mut compiler = Compiler::new().unwrap();
    /// // Add the variables
    /// compiler.define_variable("file_name", "thing.txt")?;
    /// compiler.define_variable("answer", 42)?;
    /// compiler.define_variable("pi", 3.14)?;
    /// compiler.define_variable("is_a_test", true)?;
    /// // Use them in rules
    /// compiler.add_rules_str(r#"
    /// rule TestExternalVariables {
    ///   condition:
    ///     file_name == "thing.txt"
    ///         and answer == 42
    ///         and pi == 3.14
    ///         and is_a_test
    /// }
    /// "#)?;
    /// # Ok::<(), yara::Error>(())
    /// ```
    pub fn define_variable<V: CompilerVariableValue>(
        &mut self,
        identifier: &str,
        value: V,
    ) -> Result<(), YaraError> {
        value.add_to_compiler(self.inner, identifier)
    }
}

impl Drop for Compiler {
    fn drop(&mut self) {
        internals::compiler_destroy(self.inner);
    }
}

/// Trait implemented by the types the compiler can use as value.
pub trait CompilerVariableValue {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError>;

    #[cfg(feature = "scanners")]
    fn assign_in_scanner(
        &self,
        scanner: *mut yara_sys::YR_SCANNER,
        identifier: &str,
    ) -> Result<(), YaraError>;
}

impl CompilerVariableValue for bool {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        internals::compiler_define_boolean_variable(compiler, identifier, *self)
    }

    #[cfg(feature = "scanners")]
    fn assign_in_scanner(
        &self,
        scanner: *mut yara_sys::YR_SCANNER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        internals::scanner_define_boolean_variable(scanner, identifier, *self)
    }
}

impl CompilerVariableValue for f64 {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        internals::compiler_define_float_variable(compiler, identifier, *self)
    }

    #[cfg(feature = "scanners")]
    fn assign_in_scanner(
        &self,
        scanner: *mut yara_sys::YR_SCANNER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        internals::scanner_define_float_variable(scanner, identifier, *self)
    }
}

impl CompilerVariableValue for i64 {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        internals::compiler_define_integer_variable(compiler, identifier, *self)
    }

    #[cfg(feature = "scanners")]
    fn assign_in_scanner(
        &self,
        scanner: *mut yara_sys::YR_SCANNER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        internals::scanner_define_integer_variable(scanner, identifier, *self)
    }
}

impl CompilerVariableValue for &str {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        internals::compiler_define_str_variable(compiler, identifier, *self)
    }

    #[cfg(feature = "scanners")]
    fn assign_in_scanner(
        &self,
        scanner: *mut yara_sys::YR_SCANNER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        internals::scanner_define_str_variable(scanner, identifier, *self)
    }
}

impl CompilerVariableValue for &CStr {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        internals::compiler_define_cstr_variable(compiler, identifier, *self)
    }

    #[cfg(feature = "scanners")]
    fn assign_in_scanner(
        &self,
        scanner: *mut yara_sys::YR_SCANNER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        internals::scanner_define_cstr_variable(scanner, identifier, *self)
    }
}
