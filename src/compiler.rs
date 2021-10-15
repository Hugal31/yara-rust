use std::ffi::CStr;
use std::fs::File;
use std::os::raw::{c_char, c_void};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle as AsRawFd;
use std::path::Path;

use crate::errors::*;
use crate::initialize::InitializationToken;
use crate::internals;
use crate::Rules;

/// Yara rules compiler
///
/// # Note
///
/// add_rules_* functions takes ownership on the compiler, because if a rule fails to compile,
/// the Compiler is corrupted. See issue [#47](https://github.com/Hugal31/yara-rust/issues/47).
pub struct Compiler {
    inner: *mut yara_sys::YR_COMPILER,
    _token: InitializationToken,
    // The user_data used by the include callback and it's associated free function
    // Safety: It must stay alive until the end of compilation or until a new callback is set
    include_user_data: Option<(*mut c_void, fn(*mut c_void))>,
}

impl std::fmt::Debug for Compiler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Compiler")
            .field("inner", &self.inner)
            .field("_token", &self._token)
            .finish()
    }
}

impl Compiler {
    /// Create a new compiler.
    pub fn new() -> Result<Self, YaraError> {
        let token = InitializationToken::new()?;

        internals::compiler_create().map(|inner| Compiler {
            inner,
            _token: token,
            include_user_data: None,
        })
    }

    /// Add rules definitions from a file.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use yara::Compiler;
    /// let compiler = Compiler::new()?;
    /// let compiler = compiler.add_rules_file("rules.txt")?;
    /// # Ok::<(), yara::Error>(())
    /// ```
    pub fn add_rules_file<P: AsRef<Path>>(self, path: P) -> Result<Compiler, Error> {
        File::open(path.as_ref())
            .map_err(|e| IoError::new(e, IoErrorKind::OpenRulesFile).into())
            .and_then(|file| internals::compiler_add_file(self.inner, &file, path, None))
            .map(|()| self)
    }

    /// Add rule definitions from a file within a namespace.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use yara::Compiler;
    /// let compiler = Compiler::new()?
    ///     .add_rules_file_with_namespace("CVE-2010-1297.yar", "flash")?;
    /// # Ok::<(), yara::Error>(())
    /// ```
    pub fn add_rules_file_with_namespace<P: AsRef<Path>>(
        self,
        path: P,
        namespace: &str,
    ) -> Result<Compiler, Error> {
        File::open(path.as_ref())
            .map_err(|e| IoError::new(e, IoErrorKind::OpenRulesFile).into())
            .and_then(|file| internals::compiler_add_file(self.inner, &file, path, Some(namespace)))
            .map(|()| self)
    }

    /// Add rule definitions from a string.
    ///
    /// # Example
    ///
    /// ```
    /// # use yara::Compiler;
    /// let mut compiler = Compiler::new()?
    ///     .add_rules_str("rule is_empty {
    ///   condition:
    ///     filesize == 0
    /// }")?;
    /// # Ok::<(), yara::Error>(())
    /// ```
    pub fn add_rules_str(self, rule: &str) -> Result<Compiler, Error> {
        internals::compiler_add_string(self.inner, rule, None).map(|()| self)
    }

    /// Add rule definition from a string within a namespace.
    ///
    /// # Example
    ///
    /// ```
    /// # use yara::Compiler;
    /// let mut compiler = Compiler::new()?
    ///     .add_rules_str_with_namespace("rule is_empty {
    ///   condition:
    ///     filesize == 0
    /// }", "misc")?;
    /// # Ok::<(), yara::Error>(())
    /// ```
    pub fn add_rules_str_with_namespace(
        self,
        rule: &str,
        namespace: &str,
    ) -> Result<Compiler, Error> {
        internals::compiler_add_string(self.inner, rule, Some(namespace)).map(|()| self)
    }

    /// Add rules definitions from a opened file.
    pub fn add_rules_fd<P: AsRef<Path>, F: AsRawFd>(
        self,
        file: &F,
        path: P,
    ) -> Result<Compiler, Error> {
        internals::compiler_add_file(self.inner, file, path, None).map(|()| self)
    }

    /// Add rules definitions from a opened file with namespace.
    pub fn add_rules_fd_with_namespace<P: AsRef<Path>, F: AsRawFd>(
        self,
        file: &F,
        path: P,
        namespace: &str,
    ) -> Result<Compiler, Error> {
        internals::compiler_add_file(self.inner, file, path, Some(namespace)).map(|()| self)
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
        internals::compiler_get_rules(self.inner).and_then(|v| unsafe {
            Rules::unsafe_try_from(v)
        })
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

    /// Sets a custom callback for the `include 'file.yara'` directive.
    ///
    /// This allows includes to be resolve in a custom way (database, network, cache, ...)
    /// instead of trying to read them on disk.
    ///
    /// The compiler takes ownership of the closure (it will be dropped at the same time)
    ///
    /// # Example
    ///
    /// ```
    /// # use yara::Compiler;
    /// # use std::collections::HashMap;
    /// let mut rules_db = HashMap::new();
    /// rules_db.insert("something.yara".to_string(), "data".to_string());
    /// let mut compiler = Compiler::new().unwrap();
    /// compiler.set_include_callback(move |name, _, _| rules_db.get(name).map(|r| r.clone()));
    /// ```
    pub fn set_include_callback<C>(&mut self, callback: C)
    where
        C: Fn(&str, Option<&str>, Option<&str>) -> Option<String> + 'static,
    {
        unsafe extern "C" fn include_callback<C>(
            include_name: *const c_char,
            calling_rule_filename: *const c_char,
            calling_rule_namespace: *const c_char,
            user_data: *mut c_void,
        ) -> *const c_char
        where
            C: Fn(&str, Option<&str>, Option<&str>) -> Option<String> + 'static,
        {
            let cb: &mut C = std::mem::transmute(user_data);

            let name = std::ffi::CStr::from_ptr(include_name);
            let name = match name.to_str() {
                Ok(s) => s,
                Err(_) => return std::ptr::null(),
            };

            let filename = match calling_rule_filename.is_null() {
                true => None,
                false => {
                    let filename = std::ffi::CStr::from_ptr(calling_rule_filename);
                    match filename.to_str() {
                        Ok(s) => Some(s),
                        Err(_) => return std::ptr::null(),
                    }
                }
            };

            let namespace = match calling_rule_namespace.is_null() {
                true => None,
                false => {
                    let namespace = std::ffi::CStr::from_ptr(calling_rule_namespace);
                    match namespace.to_str() {
                        Ok(s) => Some(s),
                        Err(_) => return std::ptr::null(),
                    }
                }
            };

            let res = match cb(name, filename, namespace) {
                Some(res) => res,
                None => return std::ptr::null(),
            };

            std::ffi::CString::new(res.into_bytes())
                .map(|s| s.into_raw() as *const _)
                .unwrap_or(std::ptr::null())
        }

        unsafe extern "C" fn free_include(ptr: *const c_char, _user_data: *mut c_void) {
            std::ffi::CString::from_raw(ptr as *mut _);
        }

        fn free_user_data<C>(user_data: *mut c_void) {
            unsafe {
                let cb: *mut C = std::mem::transmute(user_data);
                let _ = Box::from_raw(cb);
            }
        }

        let callback = Box::new(callback);
        let user_data = Box::leak(callback) as *mut _ as *mut c_void;
        unsafe {
            // Safety: the compiler is valid
            yara_sys::yr_compiler_set_include_callback(
                self.inner,
                Some(include_callback::<C>),
                Some(free_include),
                user_data,
            );
        }

        if let Some((data, free)) = self.include_user_data.take() {
            free(data);
        }
        self.include_user_data = Some((user_data, free_user_data::<C>));
    }

    /// Disables the support for the `include 'file.yara'` directive
    pub fn disable_include_directive(&mut self) {
        unsafe {
            // Safety: the compiler is valid
            yara_sys::yr_compiler_set_include_callback(
                self.inner,
                None,
                None,
                std::ptr::null_mut(),
            );
        }
    }
}

impl Drop for Compiler {
    fn drop(&mut self) {
        internals::compiler_destroy(self.inner);
        if let Some((data, free)) = self.include_user_data.take() {
            free(data);
        }
    }
}

/// Trait implemented by the types the compiler can use as value.
pub trait CompilerVariableValue {
    fn add_to_compiler(
        &self,
        compiler: *mut yara_sys::YR_COMPILER,
        identifier: &str,
    ) -> Result<(), YaraError>;

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

    fn assign_in_scanner(
        &self,
        scanner: *mut yara_sys::YR_SCANNER,
        identifier: &str,
    ) -> Result<(), YaraError> {
        internals::scanner_define_cstr_variable(scanner, identifier, *self)
    }
}
