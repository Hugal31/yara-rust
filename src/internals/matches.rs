use std::marker;
use std::slice;

use crate::Match;

/// Iterate over YR_MATCH in a YR_MATCHES
///
/// # Implementation notes
///
/// See `yr_string_matches_foreach` in Yara.
pub struct MatchIterator<'a> {
    head: *const yara_sys::YR_MATCH,
    _marker: marker::PhantomData<&'a yara_sys::YR_MATCH>,
}

impl<'a> From<&'a yara_sys::YR_MATCHES> for MatchIterator<'a> {
    fn from(matches: &'a yara_sys::YR_MATCHES) -> MatchIterator<'a> {
        MatchIterator {
            head: matches.head,
            _marker: marker::PhantomData,
        }
    }
}

impl<'a> Iterator for MatchIterator<'a> {
    type Item = &'a yara_sys::YR_MATCH;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.head.is_null() {
            let m = unsafe { &*self.head };
            self.head = m.next;
            // Do not list private matches, see `yr_string_matches_foreach` in libyara.
            if !m.is_private {
                return Some(m);
            }
        }
        None
    }
}

impl<'a> From<&'a yara_sys::YR_MATCH> for Match {
    fn from(m: &yara_sys::YR_MATCH) -> Self {
        Match {
            base: m.base as usize,
            offset: m.offset as usize,
            length: m.match_length as usize,
            // Data can be null, notably when the match is empty, which can happen
            // in some edge cases when using regexes.
            data: if m.data.is_null() {
                Vec::new()
            } else {
                Vec::from(unsafe { slice::from_raw_parts(m.data, m.data_length as usize) })
            },
            xor_key: m.xor_key,
        }
    }
}
