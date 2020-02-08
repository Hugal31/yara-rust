use std::ffi::{CStr, CString};
use std::marker;
use std::os::raw::c_char;
use std::ptr;

use crate::errors::*;
use crate::internals::meta::MetadataIterator;
use crate::internals::string::YrStringIterator;
use crate::{Metadata, Rule, YrString};

pub fn rules_destroy(rules: *mut yara_sys::YR_RULES) {
    unsafe {
        yara_sys::yr_rules_destroy(rules);
    }
}

// TODO Check if non mut
pub fn rules_save(rules: *mut yara_sys::YR_RULES, filename: &str) -> Result<(), YaraError> {
    let filename = CString::new(filename).unwrap();
    let result = unsafe { yara_sys::yr_rules_save(rules, filename.as_ptr()) };
    yara_sys::Error::from_code(result).map_err(|e| e.into())
}

pub fn rules_load(filename: &str) -> Result<*mut yara_sys::YR_RULES, YaraError> {
    let filename = CString::new(filename).unwrap();
    let mut pointer: *mut yara_sys::YR_RULES = ptr::null_mut();
    let result = unsafe { yara_sys::yr_rules_load(filename.as_ptr(), &mut pointer) };
    yara_sys::Error::from_code(result)
        .map(|()| pointer)
        .map_err(|e| e.into())
}

impl<'a> From<&'a yara_sys::YR_RULE> for Rule<'a> {
    fn from(rule: &'a yara_sys::YR_RULE) -> Self {
        let identifier = unsafe { CStr::from_ptr(rule.get_identifier()) }
            .to_str()
            .unwrap();
        let namespace = unsafe { CStr::from_ptr((&*rule.get_ns()).get_name()) }
            .to_str()
            .unwrap();
        let metadatas = MetadataIterator::from(rule).map(Metadata::from).collect();
        let tags = TagIterator::from(rule)
            .map(|c| c.to_str().unwrap())
            .collect();
        let strings = YrStringIterator::from(rule).map(YrString::from).collect();

        Rule {
            identifier,
            namespace,
            metadatas,
            tags,
            strings,
        }
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
