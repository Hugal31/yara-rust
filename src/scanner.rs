use std::fs::File;
use std::marker::PhantomData;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle as AsRawFd;
use std::path::Path;

use crate::compiler::CompilerVariableValue;
use crate::errors::*;
use crate::flags::ScanFlags;
use crate::internals::{
    self, CallbackMsg, CallbackReturn, MemoryBlockIterator, MemoryBlockIteratorSized,
};
use crate::rules::{Rule, Rules};

/// A wrapper around compiled [Rules], with its own set of external variables, flags and timeout.
///
/// Obtained from calling [`scanner`](crate::Rules::scanner) on a set of compiled [Rules].
///
/// Scanners are really useful in multi-threaded contexts: from a given set of Rules,
/// you can create as many Scanners as you want, and they can each have different
/// external variables defined, flags and timeout without affecting the rest of
/// the Scanners.
///
/// Contrary to compiling a new set of rules, Scanners are really lightweight to
/// create from already compiled rules.
///
/// A Scanner is bound to the lifetime of its Rules, so it can never outlive them.
///
/// # Example
///
/// ```
/// # use yara::Compiler;
/// let mut compiler = Compiler::new()?;
/// // You MUST declare external variables and default values at compile time.
/// compiler.define_variable("habitat", "land")?;
/// compiler.define_variable("is_cute", false)?;
/// compiler = compiler.add_rules_str(r#"rule is_ferris {
///   strings:
///     $rust = "rust" nocase
///   condition:
///     $rust and habitat == "ocean" and is_cute
/// }"#)?;
/// let rules = compiler.compile_rules().unwrap();
/// let mut scanner = rules.scanner().unwrap();
/// // You can then redefine the values you want, and other scanners won't be
/// // affected by it.
/// scanner.define_variable("habitat", "ocean").unwrap();
/// scanner.define_variable("is_cute", true).unwrap();
/// scanner.set_timeout(5);
/// let results = scanner.scan_mem("I love Rust!".as_bytes()).unwrap();
/// assert_eq!(1, results.len());
///
/// let is_ferris_rule = &results[0];
/// assert_eq!("is_ferris", is_ferris_rule.identifier);
/// assert_eq!(1, is_ferris_rule.strings.len());
///
/// let string = &is_ferris_rule.strings[0];
/// assert_eq!("$rust", string.identifier);
///
/// let m = &string.matches[0];
/// assert_eq!(7, m.offset);
/// assert_eq!(4, m.length);
/// assert_eq!(b"Rust", m.data.as_slice());
/// # Ok::<(), yara::Error>(())
/// ```
pub struct Scanner<'rules> {
    inner: *mut yara_sys::YR_SCANNER,
    rules: PhantomData<&'rules Rules>,
}

// On the subject of thread-safety:
// scanner_scan_XXX functions use 2 Thread Local Storage variables which would
// normally prevent the YR_SCANNER struct from being `Send` and `Sync`:
//
// * libyara.c:yr_tidx_key. This is a per-thread id allocated at the start of
//   yr_scanner_scan_mem_blocks, which is used to index into various arrays during
//   the scan. It is deallocated when yr_scanner_scan_mem_blocks returns.
//   Because we do not let the user pass its own callback to scan_XXX, and because
//   ours does not change thread or call .await, we know for a fact that there is
//   no way for our execution flow to change thread during the call to a scan_XXX,
//   hence having it Send is safe.
// * libyara.c:yr_recovery_state_key. Per thread longjmp context for internal error
//   management inside libyara. Safe on the same basis as yr_tidx_key.
//
/// This is safe because Yara TLS have are short-lived and we control the callback,
/// ensuring we cannot change thread while they are defined.
unsafe impl<'a> std::marker::Send for Scanner<'a> {}
unsafe impl<'a> std::marker::Sync for Scanner<'a> {}

impl<'a> Scanner<'a> {
    /// Creates a scanner bound to the lifetime of the Rules.
    pub(crate) fn new(rules: &'a Rules) -> Result<Scanner<'a>, YaraError> {
        // note: The scanner will inherit the external variables currently defined
        // on the Rules by copying them, but because we provide no way to assign
        // external variables directly on the Rules, this is not a concern for us.
        Ok(Scanner {
            inner: internals::scanner_create(rules.inner)?,
            rules: PhantomData,
        })
    }
}

impl<'a> Drop for Scanner<'a> {
    fn drop(&mut self) {
        internals::scanner_destroy(self.inner);
    }
}

impl<'rules> Scanner<'rules> {
    /// Define an external variable for this scanner, without affecting the
    /// rest of the scanners.
    ///
    /// Note that the variable must have already been declared with the proper type
    /// with [define_variable](crate::Compiler::define_variable) when compiling the rules.
    pub fn define_variable<V: CompilerVariableValue>(
        &mut self,
        identifier: &str,
        value: V,
    ) -> Result<(), YaraError> {
        value.assign_in_scanner(self.inner, identifier)
    }

    /// Scan memory.
    ///
    /// Returns a `Vec` of matching rules.
    ///
    /// * `mem` - Slice to scan.
    ///
    /// # Ownership
    ///
    /// This funciton takes the Scanner as `&mut` because it modifies the
    /// `scanner->callback` and `scanner->user_data`, which are not behind a Mutex.
    pub fn scan_mem(&mut self, mem: &[u8]) -> Result<Vec<Rule<'rules>>, YaraError> {
        let mut results: Vec<Rule> = Vec::new();
        let callback = |message| {
            if let internals::CallbackMsg::RuleMatching(rule) = message {
                results.push(rule)
            }
            internals::CallbackReturn::Continue
        };
        self.scan_mem_callback(mem, callback).map(|_| results)
    }

    /// Scan memory with custom callback
    ///
    /// Returns
    ///
    /// * `mem` - Slice to scan
    /// * `callback` - YARA callback more read [here](https://yara.readthedocs.io/en/stable/capi.html#scanning-data)
    ///
    /// # Ownership
    ///
    /// This funciton takes the Scanner as `&mut` because it modifies the
    /// `scanner->callback` and `scanner->user_data`, which are not behind a Mutex.
    pub fn scan_mem_callback<'r>(
        &mut self,
        mem: &[u8],
        callback: impl FnMut(CallbackMsg<'r, 'r>) -> CallbackReturn,
    ) -> Result<(), YaraError> {
        internals::scanner_scan_mem(self.inner, mem, callback)
    }

    /// Scan a file.
    ///
    /// Return a `Vec` of matching rules.
    ///
    /// # Ownership
    ///
    /// This function takes the Scanner as `&mut` because it modifies the
    /// `scanner->callback` and `scanner->user_data`, which are not behind a Mutex.
    pub fn scan_file<'r, P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<Rule<'r>>, Error> {
        let mut results: Vec<Rule> = Vec::new();
        let callback = |message| {
            if let internals::CallbackMsg::RuleMatching(rule) = message {
                results.push(rule)
            }
            internals::CallbackReturn::Continue
        };

        self.scan_file_callback(path, callback).map(|_| results)
    }

    /// Scan file with custom callback
    ///
    /// Returns
    ///
    /// * `path` - Path to file
    /// * `callback` - YARA callback more read [here](https://yara.readthedocs.io/en/stable/capi.html#scanning-data)
    ///
    /// # Ownership
    ///
    /// This function takes the Scanner as `&mut` because it modifies the
    /// `scanner->callback` and `scanner->user_data`, which are not behind a Mutex.
    pub fn scan_file_callback<'r, P: AsRef<Path>>(
        &mut self,
        path: P,
        callback: impl FnMut(CallbackMsg<'r, 'r>) -> CallbackReturn,
    ) -> Result<(), Error> {
        File::open(path)
            .map_err(|e| IoError::new(e, IoErrorKind::OpenScanFile).into())
            .and_then(|file| {
                internals::scanner_scan_file(self.inner, &file, callback).map_err(|e| e.into())
            })
    }

    /// Attach a process, pause it, and scan its memory.
    ///
    /// Return a `Vec` of matching rules.
    ///
    /// # Permissions
    ///
    /// You need to be able to attach to process `pid`.
    ///
    /// # Ownership
    ///
    /// This function takes the Scanner as `&mut` because it modifies the
    /// `scanner->callback` and `scanner->user_data`, which are not behind a Mutex.
    pub fn scan_process<'r>(&mut self, pid: u32) -> Result<Vec<Rule<'r>>, YaraError> {
        let mut results: Vec<Rule> = Vec::new();
        let callback = |message| {
            if let internals::CallbackMsg::RuleMatching(rule) = message {
                results.push(rule)
            }
            internals::CallbackReturn::Continue
        };
        self.scan_process_callback(pid, callback).map(|_| results)
    }

    /// Attach a process, pause it, and scan its memory.
    ///
    /// Returns
    ///
    /// * `pid` - Process id
    /// * `callback` - YARA callback more read [here](https://yara.readthedocs.io/en/stable/capi.html#scanning-data)
    ///
    /// # Permissions
    ///
    /// You need to be able to attach to process `pid`.
    ///
    /// # Ownership
    ///
    /// This function takes the Scanner as `&mut` because it modifies the
    /// `scanner->callback` and `scanner->user_data`, which are not behind a Mutex.
    pub fn scan_process_callback<'r>(
        &mut self,
        pid: u32,
        callback: impl FnMut(CallbackMsg<'r, 'r>) -> CallbackReturn,
    ) -> Result<(), YaraError> {
        internals::scanner_scan_proc(self.inner, pid, callback)
    }

    /// Scan a opened file.
    ///
    /// Return a `Vec` of matching rules.
    ///
    /// * `file` - the object that implements get raw file descriptor or file handle
    pub fn scan_fd<'r, F: AsRawFd>(&self, file: &F) -> Result<Vec<Rule<'r>>, Error> {
        let mut results: Vec<Rule> = Vec::new();
        let callback = |message: CallbackMsg<'r, 'r>| {
            if let CallbackMsg::RuleMatching(rule) = message {
                results.push(rule)
            }
            CallbackReturn::Continue
        };
        self.scan_fd_callback(file, callback).map(|_| results)
    }

    /// Scan a opened file with custom callback
    ///
    /// Returns
    ///
    /// * `file` - the object that implements get raw file descriptor or file handle
    /// * `callback` - YARA callback more read [here](https://yara.readthedocs.io/en/stable/capi.html#scanning-data)
    pub fn scan_fd_callback<'r, F: AsRawFd>(
        &self,
        file: &F,
        callback: impl FnMut(CallbackMsg<'r, 'r>) -> CallbackReturn,
    ) -> Result<(), Error> {
        internals::scanner_scan_file(self.inner, file, callback).map_err(|e| e.into())
    }

    /// Scan a series of memory blocks
    ///
    /// Return a `Vec` of matching rules.
    ///
    /// * `iter` - the iterator over [MemoryBlock](internals::MemoryBlock)
    pub fn scan_mem_blocks<'r>(
        &self,
        iter: impl MemoryBlockIterator,
    ) -> Result<Vec<Rule<'r>>, Error> {
        let mut results: Vec<Rule> = Vec::new();
        let callback = |message: CallbackMsg<'r, 'r>| {
            if let CallbackMsg::RuleMatching(rule) = message {
                results.push(rule)
            }
            CallbackReturn::Continue
        };
        self.scan_mem_blocks_callback(iter, callback)
            .map(|_| results)
    }

    /// Scan a series of memory blocks
    ///
    /// Returns
    ///
    /// * `iter` - the iterator over [MemoryBlock](internals::MemoryBlock)
    /// * `callback` - YARA callback more read [here](https://yara.readthedocs.io/en/stable/capi.html#scanning-data)
    pub fn scan_mem_blocks_callback<'r>(
        &self,
        iter: impl MemoryBlockIterator,
        callback: impl FnMut(CallbackMsg<'r, 'r>) -> CallbackReturn,
    ) -> Result<(), Error> {
        internals::scanner_scan_mem_blocks(self.inner, iter, callback).map_err(|e| e.into())
    }

    /// Scan a series of memory blocks with size
    ///
    /// Return a `Vec` of matching rules.
    ///
    /// * `iter` - the iterator over [MemoryBlock](internals::MemoryBlock) with size
    pub fn scan_mem_blocks_sized<'r>(
        &self,
        iter: impl MemoryBlockIteratorSized,
    ) -> Result<Vec<Rule<'r>>, Error> {
        let mut results: Vec<Rule> = Vec::new();
        let callback = |message: CallbackMsg<'r, 'r>| {
            if let CallbackMsg::RuleMatching(rule) = message {
                results.push(rule)
            }
            CallbackReturn::Continue
        };
        self.scan_mem_blocks_sized_callback(iter, callback)
            .map(|_| results)
    }

    /// Scan a series of memory blocks with size
    ///
    /// Returns
    ///
    /// * `iter` - the iterator over [MemoryBlock](internals::MemoryBlock) with size
    /// * `callback` - YARA callback more read [here](https://yara.readthedocs.io/en/stable/capi.html#scanning-data)
    pub fn scan_mem_blocks_sized_callback<'r>(
        &self,
        iter: impl MemoryBlockIteratorSized,
        callback: impl FnMut(CallbackMsg<'r, 'r>) -> CallbackReturn,
    ) -> Result<(), Error> {
        internals::scanner_scan_mem_blocks_sized(self.inner, iter, callback).map_err(|e| e.into())
    }

    /// Set the maximum number of seconds that the scanner will spend in any call
    /// to scan_xxx.
    pub fn set_timeout(&mut self, seconds: i32) {
        internals::scanner_set_timeout(self.inner, seconds)
    }

    /// Set the flags that will be used by any call to scan_xxx .
    pub fn set_flags(&mut self, flags: ScanFlags) {
        internals::scanner_set_flags(self.inner, flags.bits())
    }
}

#[cfg(test)]
mod test {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    use crate::Compiler;

    static RULES: &str = r#"rule is_ferris {
        strings:
            $rust = "rust" nocase
        condition:
            $rust and habitat == "ocean" and life_expectancy <= 10 and size < 0.3 and is_cute
        }
    "#;

    #[test]
    fn external_vars_on_file() {
        let mut compiler = Compiler::new().unwrap();
        // You MUST declare external variables and default values at compile time.
        compiler.define_variable("habitat", "land").unwrap();
        compiler.define_variable("life_expectancy", 99).unwrap();
        compiler.define_variable("size", 1.0_f64).unwrap();
        compiler.define_variable("is_cute", false).unwrap();
        let rules = compiler
            .add_rules_str(RULES)
            .unwrap()
            .compile_rules()
            .unwrap();
        // Create two scanners, with different variable definitions:
        // a crab, and a Rust gamer.
        let mut scanner1 = rules.scanner().unwrap();
        let mut scanner2 = rules.scanner().unwrap();
        scanner1.define_variable("habitat", "ocean").unwrap();
        scanner1.define_variable("life_expectancy", 5).unwrap();
        scanner1.define_variable("size", 0.20_f64).unwrap();
        scanner1.define_variable("is_cute", true).unwrap();
        scanner1.set_timeout(5);
        scanner2.define_variable("habitat", "his house").unwrap();
        scanner2.define_variable("life_expectancy", 82).unwrap();
        scanner2.define_variable("size", 1.75_f64).unwrap();
        scanner2.define_variable("is_cute", false).unwrap();
        scanner2.set_timeout(10);

        let mut file = tempfile::NamedTempFile::new().expect("temp file creation to succeed");
        file.write_all("I love Rust!".as_bytes())
            .expect("write to tempfile to succeed");
        let results1 = scanner1
            .scan_file(
                file.path()
                    .to_str()
                    .expect("tempfile path to be valid utf-8"),
            )
            .unwrap();
        let results2 = scanner2
            .scan_file(
                file.path()
                    .to_str()
                    .expect("tempfile path to be valid utf-8"),
            )
            .unwrap();
        assert_eq!(1, results1.len());
        assert_eq!(0, results2.len());

        let is_ferris_rule = &results1[0];
        assert_eq!("is_ferris", is_ferris_rule.identifier);
        assert_eq!(1, is_ferris_rule.strings.len());

        let string = &is_ferris_rule.strings[0];
        assert_eq!("$rust", string.identifier);

        let m = &string.matches[0];
        assert_eq!(7, m.offset);
        assert_eq!(4, m.length);
        assert_eq!(b"Rust", m.data.as_slice());
    }

    /// A random uuid that should be present in the process memory for the rule
    /// to match.
    static UUID_MATCH: &str = "401d67bf-ff9c-4632-992e-46afed0bbcff";
    /// A random uuid that is unlikely to be present in the process' memory.
    static UUID_NO_MATCH: &str = "db4f9dab-a622-4fc9-b71f-38398baf308b";

    #[cfg(not(windows))]
    static RULES_PROC: &str = r#"rule found_uuid {
        strings:
            $target = "401d67bf-ff9c-4632-992e-46afed0bbcff"
        condition:
            $target
        }
    "#;
    #[cfg(windows)]
    static RULES_PROC: &str = r#"rule found_uuid {
        strings:
            $target = "401d67bf-ff9c-4632-992e-46afed0bbcff" wide
        condition:
            $target
        }
    "#;

    #[test]
    fn scanner_scan_proc() {
        let compiler = Compiler::new().unwrap().add_rules_str(RULES_PROC).unwrap();
        let rules = compiler.compile_rules().unwrap();
        let mut scanner = rules.scanner().unwrap();
        scanner.set_timeout(10);

        // spawn two process, one which should match and one that should not
        #[cfg(unix)]
        let process_match = Command::new("sh")
            .arg("-c")
            .arg(format!("sleep 5; echo {}", UUID_MATCH))
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        #[cfg(unix)]
        let process_no_match = Command::new("sh")
            .arg("-c")
            .arg(format!("sleep 5; echo {}", UUID_NO_MATCH))
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        #[cfg(windows)]
        let process_match = Command::new("cmd")
            .arg("/C")
            .arg(format!("ping 127.0.0.1 -n 60 > nul & echo {}", UUID_MATCH))
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        #[cfg(windows)]
        let process_no_match = Command::new("cmd")
            .arg("/C")
            .arg(format!(
                "ping 127.0.0.1 -n 60 > nul & echo {}",
                UUID_NO_MATCH
            ))
            .stdout(Stdio::null())
            .spawn()
            .unwrap();

        let results1 = scanner.scan_process(process_match.id()).unwrap();
        let results2 = scanner.scan_process(process_no_match.id()).unwrap();
        assert_eq!(1, results1.len());
        assert_eq!(0, results2.len());

        let found_uuid = &results1[0];
        assert_eq!("found_uuid", found_uuid.identifier);
        assert_eq!(1, found_uuid.strings.len());

        for string in &found_uuid.strings {
            assert_eq!("$target", string.identifier);

            let bytes = if cfg!(windows) {
                // the string is in utf-16 format, filter out the zeroes.
                string.matches[0]
                    .data
                    .clone()
                    .into_iter()
                    .filter(|v| *v != 0)
                    .collect()
            } else {
                string.matches[0].data.clone()
            };
            assert_eq!(UUID_MATCH.as_bytes(), bytes);
        }
    }
}
