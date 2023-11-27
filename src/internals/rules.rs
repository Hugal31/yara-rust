use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::marker;
use std::os::raw::c_char;
use std::ptr;

use crate::errors::*;
use crate::internals::meta::MetadataIterator;
use crate::internals::string::YrStringIterator;
use crate::rules::RulesetRule;
use crate::{Metadata, Rule, YrString};

pub fn rules_destroy(rules: *mut yara_sys::YR_RULES) {
    unsafe {
        yara_sys::yr_rules_destroy(rules);
    }
}

pub fn scanner_create(
    rules: *mut yara_sys::YR_RULES,
) -> Result<*mut yara_sys::YR_SCANNER, YaraError> {
    let mut new_scanner: *mut yara_sys::YR_SCANNER = std::ptr::null_mut();

    let result = unsafe { yara_sys::yr_scanner_create(rules, &mut new_scanner) };

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| new_scanner)
}

pub fn scanner_destroy(scanner: *mut yara_sys::YR_SCANNER) {
    unsafe {
        yara_sys::yr_scanner_destroy(scanner);
    }
}

pub fn get_rules<'a>(ruleset: *mut yara_sys::YR_RULES) -> Vec<RulesetRule<'a>> {
    let num_rules = unsafe { (*ruleset).num_rules } as usize;
    let mut result: Vec<RulesetRule> = Vec::with_capacity(num_rules);

    for rule in RuleIterator::from(unsafe { &*ruleset }) {
        result.push(rule);
    }

    result
}

// TODO Check if non mut
pub fn rules_save(rules: *mut yara_sys::YR_RULES, filename: &str) -> Result<(), YaraError> {
    let filename = CString::new(filename).unwrap();
    let result = unsafe { yara_sys::yr_rules_save(rules, filename.as_ptr()) };
    yara_sys::Error::from_code(result).map_err(|e| e.into())
}

pub fn rules_save_stream<W>(rules: *mut yara_sys::YR_RULES, mut writer: W) -> Result<(), Error>
where
    W: Write,
{
    let mut write_stream = super::stream::WriteStream::new(&mut writer);
    let mut yr_stream = write_stream.as_yara();
    let result = unsafe { yara_sys::yr_rules_save_stream(rules, &mut yr_stream) };

    write_stream
        .result()
        .map_err(|e| IoError::new(e, IoErrorKind::WritingRules).into())
        .and_then(|_| {
            yara_sys::Error::from_code(result)
                .map_err(From::from)
                .map_err(|e: YaraError| e.into())
        })
}

pub fn rules_load(filename: &str) -> Result<*mut yara_sys::YR_RULES, YaraError> {
    let filename = CString::new(filename).unwrap();
    let mut pointer: *mut yara_sys::YR_RULES = ptr::null_mut();
    let result = unsafe { yara_sys::yr_rules_load(filename.as_ptr(), &mut pointer) };
    yara_sys::Error::from_code(result)
        .map(|()| pointer)
        .map_err(|e| e.into())
}

pub fn rules_load_stream<R>(mut reader: R) -> Result<*mut yara_sys::YR_RULES, Error>
where
    R: Read,
{
    let mut read_stream = super::stream::ReadStream::new(&mut reader);
    let mut yr_stream = read_stream.as_yara();
    let mut pointer: *mut yara_sys::YR_RULES = ptr::null_mut();
    let result = unsafe { yara_sys::yr_rules_load_stream(&mut yr_stream, &mut pointer) };

    read_stream
        .result()
        .map(|()| pointer)
        .map_err(|e| IoError::new(e, IoErrorKind::ReadingRules).into())
        .and_then(|pointer| {
            yara_sys::Error::from_code(result)
                .map(|_| pointer)
                .map_err(From::from)
                .map_err(|e: YaraError| e.into())
        })
}

impl<'a> From<&'a yara_sys::YR_RULE> for Rule<'a> {
    fn from(rule: &'a yara_sys::YR_RULE) -> Self {
        let identifier = unsafe { CStr::from_ptr(rule.get_identifier()) }
            .to_str()
            .unwrap();
        let namespace = unsafe { CStr::from_ptr((*rule.get_ns()).get_name()) }
            .to_str()
            .unwrap();
        let metadatas = MetadataIterator::from(rule).map(Metadata::from).collect();
        let tags = TagIterator::from(rule)
            .map(|c| c.to_str().unwrap())
            .collect();
        let strings: Vec<YrString> = Vec::new();

        Rule {
            identifier,
            namespace,
            metadatas,
            tags,
            strings,
        }
    }
}

impl<'a> From<(&'a yara_sys::YR_SCAN_CONTEXT, &'a yara_sys::YR_RULE)> for Rule<'a> {
    fn from((context, rule): (&'a yara_sys::YR_SCAN_CONTEXT, &'a yara_sys::YR_RULE)) -> Self {
        let mut result = Rule::from(rule);
        result.strings = YrStringIterator::from(rule)
            .map(|s| YrString::from((context, s)))
            .collect();
        result
    }
}

/// Iterate over YR_RULE in a YR_RULES.
///
/// # Implementation notes
///
/// See `yr_rules_foreach` in Yara.
pub struct RuleIterator<'a> {
    head: *const yara_sys::YR_RULE,
    _marker: marker::PhantomData<&'a yara_sys::YR_RULE>,
}

impl<'a> From<&'a yara_sys::YR_RULES> for RuleIterator<'a> {
    fn from(rules: &'a yara_sys::YR_RULES) -> RuleIterator<'a> {
        RuleIterator {
            head: rules.get_rules_table(),
            _marker: marker::PhantomData,
        }
    }
}

impl<'a> Iterator for RuleIterator<'a> {
    type Item = RulesetRule<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.head.is_null() {
            return None;
        }

        let rule = unsafe { *self.head };
        let mut result: Option<Self::Item> = None;

        if ((rule.flags as u32) & yara_sys::RULE_FLAGS_NULL) != 0 {
            self.head = std::ptr::null();
        } else {
            let rule_data = Rule::from(unsafe { &*self.head });
            result = Some(RulesetRule {
                inner: self.head as *mut yara_sys::YR_RULE,
                identifier: rule_data.identifier,
                namespace: rule_data.namespace,
                tags: rule_data.tags,
                metadatas: rule_data.metadatas,
            });
            self.head = unsafe { self.head.offset(1) };
        }
        result
    }
}

struct TagIterator<'a> {
    head: *const c_char,
    _marker: marker::PhantomData<&'a c_char>,
}

impl<'a> From<&'a yara_sys::YR_RULE> for TagIterator<'a> {
    fn from(rule: &'a yara_sys::YR_RULE) -> Self {
        TagIterator {
            head: rule.get_tags(),
            _marker: Default::default(),
        }
    }
}

impl<'a> Iterator for TagIterator<'a> {
    type Item = &'a CStr;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.head.is_null() && unsafe { *self.head } != 0 {
            let s = unsafe { CStr::from_ptr(self.head) };
            self.head = unsafe { self.head.add(s.to_bytes_with_nul().len()) };
            Some(s)
        } else {
            None
        }
    }
}
