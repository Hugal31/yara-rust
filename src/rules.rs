use std::convert::TryFrom;
use std::fs::File;
use std::path::Path;

use failure::ResultExt;
use yara_sys;

use crate::{errors::*, initialize::InitializationToken, internals, YrString};

/// A set of rules.
pub struct Rules {
    inner: *mut yara_sys::YR_RULES,
    pub(crate) _token: InitializationToken,
}

/// This is safe because Yara have a mutex on the YR_RULES
unsafe impl std::marker::Sync for Rules {}

impl TryFrom<*mut yara_sys::YR_RULES> for Rules {
    type Error = YaraError;

    fn try_from(rules: *mut yara_sys::YR_RULES) -> Result<Self, Self::Error> {
        let token = InitializationToken::new()?;

        Ok(Rules {
            inner: rules,
            _token: token,
        })
    }
}

impl Rules {
    /// Scan memory
    ///
    /// * `mem` - Slice to scan.
    /// * `timeout` - the timeout is in seconds.
    ///
    /// # Example
    ///
    /// ```
    /// # use yara::Yara;
    /// let mut yara = Yara::create().unwrap();
    /// let mut compiler = yara.new_compiler().unwrap();
    /// compiler.add_rules_str("rule contains_rust {
    ///   strings:
    ///     $rust = \"rust\" nocase
    ///   condition:
    ///     $rust
    /// }").unwrap();
    /// let mut rules = compiler.compile_rules().unwrap();
    /// let results = rules.scan_mem("I love Rust!".as_bytes(), 5).unwrap();
    /// assert_eq!(1, results.len());
    ///
    /// let rule = &results[0];
    /// assert_eq!("contains_rust", rule.identifier);
    /// assert_eq!(1, rule.strings.len());
    ///
    /// let string = &rule.strings[0];
    /// assert_eq!("$rust", string.identifier);
    ///
    /// let m = &string.matches[0];
    /// assert_eq!(7, m.offset);
    /// assert_eq!(4, m.length);
    /// assert_eq!(b"Rust", m.data.as_slice());
    /// ```
    pub fn scan_mem(&self, mem: &[u8], timeout: u16) -> Result<Vec<Rule>, YaraError> {
        internals::rules_scan_mem(self.inner, mem, i32::from(timeout))
    }

    pub fn scan_file<'r, P: AsRef<Path>>(
        &self,
        path: P,
        timeout: u16,
    ) -> Result<Vec<Rule<'r>>, Error> {
        File::open(path)
            .context(IoErrorKind::OpenScanFile)
            .map_err(|e| Into::<IoError>::into(e).into())
            .and_then(|file| {
                internals::rules_scan_file(self.inner, &file, i32::from(timeout))
                    .map_err(|e| e.into())
            })
    }

    /// Save the rules to a file.
    // TODO Check if mut is necessary.
    // TODO Take AsRef<Path> ?
    pub fn save(&mut self, filename: &str) -> Result<(), YaraError> {
        internals::rules_save(self.inner, filename)
    }

    /// Load rules from a pre-compiled rules file.
    // TODO Take AsRef<Path> ?
    pub fn load_from_file(filename: &str) -> Result<Self, YaraError> {
        let token = InitializationToken::new()?;

        internals::rules_load(filename).map(|inner| Rules {
            inner,
            _token: token,
        })
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

#[derive(Debug, Eq, PartialEq)]
pub struct Metadata<'r> {
    pub identifier: &'r str,
    pub value: MetadataValue<'r>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MetadataValue<'r> {
    Integer(i64),
    String(&'r str),
    Boolean(bool),
}
