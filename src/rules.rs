use yara_sys;

use errors::*;
use internals;

/// A set of rules.
pub struct Rules<'a> {
    inner: &'a mut yara_sys::YR_RULES,
}

impl<'a> From<&'a mut yara_sys::YR_RULES> for Rules<'a> {
    fn from(rules: &'a mut yara_sys::YR_RULES) -> Rules<'a> {
        Rules { inner: rules }
    }
}

impl<'a> Rules<'a> {
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
    pub fn scan_mem(&mut self, mem: &[u8], timeout: u16) -> Result<Vec<Rule<'a>>, YaraError> {
        internals::rules_scan_mem(self.inner, mem, i32::from(timeout))
    }

    /// Save the rules to a file.
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

/// A rule that matched during a scan.
// TODO Add other fields as metadata.
#[derive(Debug)]
pub struct Rule<'a> {
    /// Name of the rule.
    pub identifier: &'a str,
    /// Matcher strings of the rule.
    pub strings: Vec<YrString<'a>>,
}

/// A matcher string that matched during a scan.
#[derive(Debug)]
pub struct YrString<'a> {
    /// Name of the string, with the '$'.
    pub identifier: &'a str,
    /// Matches of the string for the scan.
    pub matches: Vec<Match>,
}

/// A match within a scan.
#[derive(Debug)]
pub struct Match {
    /// Offset of the match within the scanning area.
    pub offset: usize,
    /// Length of the file. Can be useful if the matcher string has not a fixed length.
    pub length: usize,
    /// Matched data.
    pub data: Vec<u8>,
}
