use yara_sys;

use errors::*;
use internals;

pub struct Rules<'a> {
    inner: &'a mut yara_sys::YR_RULES,
}

impl<'a> Rules<'a> {
    pub(crate) fn from(rules: &'a mut yara_sys::YR_RULES) -> Rules<'a> {
        Rules { inner: rules }
    }

    /// Scan memory
    ///
    /// The timeout is in seconds
    pub fn scan_mem(&mut self, mem: &[u8], timeout: u16) -> Result<Vec<Rule>, YaraError> {
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

#[derive(Debug)]
pub struct Rule {
    pub identifier: String,
    pub strings: Vec<YrString>,
}

#[derive(Debug)]
pub struct YrString {
    pub identifier: String,
    pub matches: Vec<Match>,
}

#[derive(Debug)]
pub struct Match {
    pub offset: usize,
    pub match_length: usize,
    pub data: Vec<u8>,
}
