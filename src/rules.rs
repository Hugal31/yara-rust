use std::convert::TryFrom;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
pub use yara_sys::scan_flags::*;

use crate::{errors::*, initialize::InitializationToken, internals, YrString};

/// A set of compiled rules.
///
/// Obtained from [compiling](struct.Compiler.html) or
/// [loading a pre-compiled rule](#method.load_from_file).
pub struct Rules {
    pub(crate) inner: *mut yara_sys::YR_RULES,
    pub(crate) _token: InitializationToken,
    flags: u32,
}

// On the subject of thread-safety:
// scan_XXX functions use 3 Thread Local Storage variables which would
// normally prevent the YR_RULES struct from being `Send`:
//
// * libyara.c:yr_tidx_key. This is a per-thread id allocated at the start of
//   yr_rules_scan_mem_blocks, which is used to index into various arrays during
//   the scan. It is deallocated when yr_rules_scan_mem_blocks returns.
//   Because we do not let the user pass its own callback to scan_XXX, and because
//   ours does not change thread or call .await, we know for a fact that there is
//   no way for our execution flow to change thread during the call to a scan_XXX,
//   hence having it Send is safe.
// * libyara.c:yr_recovery_state_key. Per thread longjmp context for internal error
//   management inside libyara. Safe on the same basis as yr_tidx_key.
// * re.c:thread_storage_key. only prior to v3.8, later removed by #823.
//   The regex engine kept per-thread allocated memory, which was freed when calling
//   yr_finalize_thread. If YR_RULES is moved, and yr_finalize_thread is called
//   from another thread, this will just be a no-op, and we will leak the memory
//   allocated by re.c on the first thread. Although this is not ideal, it is
//   technically considered safe Rust. We instead chose to call finalize_thread()
//   for every scan_XXX call we make.
//
/// This is safe because Yara TLS have are short-lived and we control the callback,
/// ensuring we cannot change thread while they are defined.
unsafe impl std::marker::Send for Rules {}
/// This is safe because Yara have a mutex on the YR_RULES
unsafe impl std::marker::Sync for Rules {}

impl TryFrom<*mut yara_sys::YR_RULES> for Rules {
    type Error = YaraError;

    fn try_from(rules: *mut yara_sys::YR_RULES) -> Result<Self, Self::Error> {
        let token = InitializationToken::new()?;

        Ok(Rules {
            inner: rules,
            _token: token,
            flags: 0,
        })
    }
}

impl Rules {
    /// Create a [`Scanner`](crate::scanner::Scanner) from this set of rules.
    ///
    /// You can create as many scanners as you want, and they each can have
    /// their own scan flag, timeout, and external variables defined.
    pub fn scanner(&self) -> Result<crate::scanner::Scanner, YaraError> {
        crate::scanner::Scanner::new(&self)
    }

    /// Scan memory.
    ///
    /// Returns a `Vec` of maching rules.
    ///
    /// * `mem` - Slice to scan.
    /// * `timeout` - the timeout is in seconds.
    ///
    /// # Example
    ///
    /// ```
    /// # use yara::Compiler;
    /// let mut compiler = Compiler::new()?;
    /// compiler.add_rules_str("rule contains_rust {
    ///   strings:
    ///     $rust = \"rust\" nocase
    ///   condition:
    ///     $rust
    /// }")?;
    /// let rules = compiler.compile_rules().unwrap();
    /// let results = rules.scan_mem("I love Rust!".as_bytes(), 5).unwrap();
    /// assert_eq!(1, results.len());
    ///
    /// let contains_rust_rule = &results[0];
    /// assert_eq!("contains_rust", contains_rust_rule.identifier);
    /// assert_eq!(1, contains_rust_rule.strings.len());
    ///
    /// let string = &contains_rust_rule.strings[0];
    /// assert_eq!("$rust", string.identifier);
    ///
    /// let m = &string.matches[0];
    /// assert_eq!(7, m.offset);
    /// assert_eq!(4, m.length);
    /// assert_eq!(b"Rust", m.data.as_slice());
    /// # Ok::<(), yara::Error>(())
    /// ```
    pub fn scan_mem(&self, mem: &[u8], timeout: u16) -> Result<Vec<Rule>, YaraError> {
        internals::rules_scan_mem(self.inner, mem, i32::from(timeout), self.flags as i32)
    }

    /// Scan a file.
    ///
    /// Return a `Vec` of matching rules.
    pub fn scan_file<'r, P: AsRef<Path>>(
        &self,
        path: P,
        timeout: u16,
    ) -> Result<Vec<Rule<'r>>, Error> {
        File::open(path)
            .map_err(|e| IoError::new(e, IoErrorKind::OpenScanFile).into())
            .and_then(|file| {
                internals::rules_scan_file(self.inner, &file, i32::from(timeout), self.flags as i32)
                    .map_err(|e| e.into())
            })
    }

    /// Attach a process, pause it, and scan its memory.
    ///
    /// Return a `Vec` of matching rules.
    ///
    /// # Permissions
    ///
    /// You need to be able to attach to process `pid`.
    pub fn scan_process<'r>(
        &self,
        pid: u32,
        timeout: u16
    ) -> Result<Vec<Rule<'r>>, YaraError> {
        internals::rules_scan_proc(self.inner, pid, i32::from(timeout), self.flags as i32)
    }

    /// Save the rules to a file.
    ///
    /// Note: this method is mut because Yara modifies the Rule arena during serialization.
    // TODO Take AsRef<Path> ?
    // Yara is expecting a *const u8 string, whereas a Path on Windows is an [u16].
    pub fn save(&mut self, filename: &str) -> Result<(), YaraError> {
        internals::rules_save(self.inner, filename)
    }

    /// Save the rules in a Writer.
    ///
    /// Note: this method is mut because Yara modifies the Rule arena during serialization.
    pub fn save_to_stream<W>(&mut self, writer: W) -> Result<(), Error>
    where
        W: Write,
    {
        internals::rules_save_stream(self.inner, writer)
    }

    /// Load rules from a pre-compiled rules file.
    pub fn load_from_stream<R: Read>(reader: R) -> Result<Self, Error> {
        let token = InitializationToken::new()?;

        internals::rules_load_stream(reader).map(|inner| Rules {
            inner,
            _token: token,
            flags: 0,
        })
    }

    /// Load rules from a pre-compiled rules file.
    // TODO Take AsRef<Path> ?
    pub fn load_from_file(filename: &str) -> Result<Self, YaraError> {
        let token = InitializationToken::new()?;

        internals::rules_load(filename).map(|inner| Rules {
            inner,
            _token: token,
            flags: 0,
        })
    }

    pub fn set_flags(&mut self, flags: u32) {
        self.flags = flags
    }
}

impl Drop for Rules {
    fn drop(&mut self) {
        internals::rules_destroy(self.inner);
    }
}

/// A rule that matched during a scan.
#[derive(Debug)]
pub struct Rule<'r> {
    /// Name of the rule.
    pub identifier: &'r str,
    /// Namespace of the rule.
    pub namespace: &'r str,
    /// Metadatas of the rule.
    pub metadatas: Vec<Metadata<'r>>,
    /// Tags of the rule.
    pub tags: Vec<&'r str>,
    /// Matcher strings of the rule.
    pub strings: Vec<YrString<'r>>,
}

/// Metadata specified in a rule.
#[derive(Debug, Eq, PartialEq)]
pub struct Metadata<'r> {
    pub identifier: &'r str,
    pub value: MetadataValue<'r>,
}

/// Type of the value in [MetaData](struct.Metadata.html)
#[derive(Debug, Eq, PartialEq)]
pub enum MetadataValue<'r> {
    Integer(i64),
    String(&'r str),
    Boolean(bool),
}

#[cfg(test)]
mod test {
    use std::process::{Command, Stdio};

    use crate::Compiler;

    /// A random uuid that should be present in the process memory for the rule
    /// to match.
    static UUID_MATCH:    &str = "401d67bf-ff9c-4632-992e-46afed0bbcff";
    /// A random uuid that is unlikely to be present in the process' memory.
    static UUID_NO_MATCH: &str = "db4f9dab-a622-4fc9-b71f-38398baf308b";

    static RULES_PROC: &str = r#"rule found_uuid {
        strings:
            $target = "401d67bf-ff9c-4632-992e-46afed0bbcff"
        condition:
            $target
        }
    "#;

    #[test]
    fn rules_scan_proc() {
        let mut compiler = Compiler::new().unwrap();
        compiler.add_rules_str(RULES_PROC).unwrap();
        let rules = compiler.compile_rules().unwrap();
        let mut scanner = rules.scanner().unwrap();
        scanner.set_timeout(10);

        // spawn two process, one which should match and one that should not
        #[cfg(unix)]
        let process_match = Command::new("sh")
            .arg("-c")
            .arg(format!("sleep 5; echo {}", UUID_MATCH))
            .stdout(Stdio::null())
            .spawn().unwrap();
        #[cfg(unix)]
        let process_no_match = Command::new("sh")
            .arg("-c")
            .arg(format!("sleep 5; echo {}", UUID_NO_MATCH))
            .stdout(Stdio::null())
            .spawn().unwrap();
        #[cfg(windows)]
        let process_match = Command::new("cmd")
            .arg("/C")
            .arg(format!("ping 127.0.0.1 -n 6 > nul & echo {}", UUID_MATCH))
            .stdout(Stdio::null())
            .spawn().unwrap();
        #[cfg(windows)]
        let process_no_match = Command::new("cmd")
            .arg("/C")
            .arg(format!("ping 127.0.0.1 -n 6 > nul & echo {}", UUID_NO_MATCH))
            .stdout(Stdio::null())
            .spawn().unwrap();

        let results1 = scanner.scan_process(process_match.id()).unwrap();
        let results2 = scanner.scan_process(process_no_match.id()).unwrap();
        assert_eq!(1, results1.len());
        assert_eq!(0, results2.len());

        let found_uuid = &results1[0];
        assert_eq!("found_uuid", found_uuid.identifier);
        assert_eq!(1, found_uuid.strings.len());

        let string = &found_uuid.strings[0];
        assert_eq!("$target", string.identifier);

        let m = &string.matches[0];
        assert_eq!(UUID_MATCH.as_bytes(), m.data.as_slice());
    }
}
