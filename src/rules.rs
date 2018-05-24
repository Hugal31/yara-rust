use yara_sys;

use errors::*;
use internals;
use YrString;

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
    /// Namespace of the rule.
    pub namespace: &'a str,
    /// Metadatas of the rule.
    pub metadatas: Vec<Metadata<'a>>,
    /// Tags of the rule.
    pub tags: Vec<&'a str>,
    /// Matcher strings of the rule.
    pub strings: Vec<YrString<'a>>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Metadata<'a> {
    pub identifier: &'a str,
    pub value: MetadataValue<'a>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MetadataValue<'a> {
    Integer(i64),
    String(&'a str),
    Boolean(bool),
}
