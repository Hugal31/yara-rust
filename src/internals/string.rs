use std::ffi::CStr;
use std::marker;

use yara_sys::{YR_SCAN_CONTEXT, YR_STRING};

use crate::internals::matches::MatchIterator;
use crate::Match;
use crate::YrString;

/// Iterate over YR_STRING in a YR_RULE.
///
/// # Implementation notes
///
/// See `yr_rule_strings_foreach` in Yara.
pub struct YrStringIterator<'a> {
    head: *const yara_sys::YR_STRING,
    _marker: marker::PhantomData<&'a yara_sys::YR_STRING>,
}

impl<'a> From<&'a yara_sys::YR_RULE> for YrStringIterator<'a> {
    fn from(rule: &'a yara_sys::YR_RULE) -> YrStringIterator<'a> {
        YrStringIterator {
            head: rule.get_strings(),
            _marker: marker::PhantomData,
        }
    }
}

impl<'a> Iterator for YrStringIterator<'a> {
    type Item = &'a yara_sys::YR_STRING;

    fn next(&mut self) -> Option<Self::Item> {
        if self.head.is_null() {
            return None;
        }

        let string = unsafe { &*self.head };

        if string.flags & yara_sys::STRING_FLAGS_LAST_IN_RULE != 0 {
            self.head = std::ptr::null();
        } else {
            self.head = unsafe { self.head.offset(1) };
        }

        Some(string)
    }
}

impl<'a> From<(&'a YR_SCAN_CONTEXT, &'a YR_STRING)> for YrString<'a> {
    fn from((context, string): (&'a YR_SCAN_CONTEXT, &'a YR_STRING)) -> Self {
        let identifier = unsafe { CStr::from_ptr(string.get_identifier()) }
            .to_str()
            .unwrap();
        let matches = unsafe { &*context.matches.offset(string.idx as isize) };
        let matches = MatchIterator::from(matches).map(Match::from).collect();

        YrString {
            identifier,
            matches,
        }
    }
}
