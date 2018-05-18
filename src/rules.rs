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
