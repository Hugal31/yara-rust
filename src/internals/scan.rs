use std::ffi::CStr;
use std::fs::File;
use std::marker;
use std::mem;
use std::os::raw::c_void;
use std::ptr;
use std::slice;

use yara_sys;

use super::get_tidx;
use Match;
use Rule;
use YrString;

use errors::*;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum CallbackMsg {
    RuleMatching,
    RuleNotMatching,
    ScanFinished,
    ImportModule,
    ModuleImported,
    UnknownMsg,
}

impl CallbackMsg {
    pub fn from_yara(code: i32) -> Self {
        use self::CallbackMsg::*;
        let code = code as u32;

        match code {
            yara_sys::CALLBACK_MSG_RULE_MATCHING => RuleMatching,
            yara_sys::CALLBACK_MSG_RULE_NOT_MATCHING => RuleNotMatching,
            yara_sys::CALLBACK_MSG_SCAN_FINISHED => ScanFinished,
            yara_sys::CALLBACK_MSG_IMPORT_MODULE => ImportModule,
            yara_sys::CALLBACK_MSG_MODULE_IMPORTED => ModuleImported,
            _ => UnknownMsg,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum CallbackReturn {
    Continue,
    Abort,
    Error,
}

impl CallbackReturn {
    pub fn to_yara(&self) -> i32 {
        use self::CallbackReturn::*;

        let res = match self {
            Continue => yara_sys::CALLBACK_CONTINUE,
            Abort => yara_sys::CALLBACK_ABORT,
            Error => yara_sys::CALLBACK_ERROR,
        };
        res as i32
    }
}

impl<'a> From<&'a yara_sys::_YR_MATCH> for Match {
    fn from(m: &'a yara_sys::_YR_MATCH) -> Self {
        Match {
            offset: m.offset as usize,
            match_length: m.match_length as usize,
            data: Vec::from(unsafe { slice::from_raw_parts(m.data, m.data_length as usize) }),
        }
    }
}

/// Should't be necessary. Or ?
impl<'a> From<&'a mut yara_sys::_YR_MATCH> for Match {
    fn from(m: &'a mut yara_sys::_YR_MATCH) -> Self {
        From::<&'a yara_sys::_YR_MATCH>::from(m)
    }
}

pub fn rules_scan_mem<'a>(
    rules: *mut yara_sys::YR_RULES,
    mem: &[u8],
    timeout: i32,
) -> Result<Vec<Rule>, YaraError> {
    let mut results = Vec::<Rule>::new();
    let result = unsafe {
        yara_sys::yr_rules_scan_mem(
            rules,
            mem.as_ptr(),
            mem.len(),
            0,
            Some(scan_callback),
            mem::transmute(&mut results),
            timeout,
        )
    };

    YaraErrorKind::from_yara(result)
        .map_err(|e| e.into())
        .map(|_| results)
}

extern "C" fn scan_callback(
    message: i32,
    message_data: *mut c_void,
    user_data: *mut c_void,
) -> i32 {
    let message = CallbackMsg::from_yara(message);
    let rules: &mut Vec<Rule> = unsafe { mem::transmute(user_data) };

    if message == CallbackMsg::RuleMatching {
        let rule: &mut yara_sys::YR_RULE = unsafe { mem::transmute(message_data) };
        rules.push(Rule {
            identifier: unsafe { CStr::from_ptr(rule.__bindgen_anon_1.identifier) }
                .to_str()
                .unwrap()
                .to_string(),
            strings: get_rule_strings(rule),
        });
    }

    CallbackReturn::Continue.to_yara()
}

// TODO: Try to remove mut
fn get_rule_strings(rule: &mut yara_sys::YR_RULE) -> Vec<YrString> {
    let tidx = get_tidx();
    YrStringIterator::from(rule)
        .map(|s| {
            let matches = MatchIterator::from(&mut s.matches[tidx as usize])
                .map(Match::from)
                .collect();
            YrString { matches }
        })
        .collect()
}

pub struct YrStringIterator<'a> {
    head: *mut yara_sys::YR_STRING,
    _marker: marker::PhantomData<&'a yara_sys::YR_STRING>,
}

impl<'a> From<&'a mut yara_sys::YR_RULE> for YrStringIterator<'a> {
    fn from(rule: &'a mut yara_sys::YR_RULE) -> YrStringIterator<'a> {
        YrStringIterator {
            head: unsafe { rule.__bindgen_anon_4.strings },
            _marker: marker::PhantomData::default(),
        }
    }
}

impl<'a> Iterator for YrStringIterator<'a> {
    type Item = &'a mut yara_sys::YR_STRING;

    fn next(&mut self) -> Option<Self::Item> {
        if self.head.is_null() {
            return None;
        }

        let string = unsafe { &mut *self.head };

        if string.g_flags as u32 & yara_sys::STRING_GFLAGS_NULL != 0 {
            None
        } else {
            self.head = unsafe { self.head.offset(1) };
            Some(string)
        }
    }
}

pub struct MatchIterator<'a> {
    head: *mut yara_sys::_YR_MATCH,
    _marker: marker::PhantomData<&'a yara_sys::_YR_MATCH>,
}

impl<'a> From<&'a mut yara_sys::YR_MATCHES> for MatchIterator<'a> {
    fn from(matches: &'a mut yara_sys::YR_MATCHES) -> MatchIterator<'a> {
        MatchIterator {
            head: unsafe { matches.__bindgen_anon_1.head },
            _marker: marker::PhantomData::default(),
        }
    }
}

impl<'a> Iterator for MatchIterator<'a> {
    type Item = &'a mut yara_sys::_YR_MATCH;

    fn next(&mut self) -> Option<Self::Item> {
        let res = ptr::NonNull::new(self.head)
            .map(ptr::NonNull::as_ptr)
            .map(|p| unsafe { &mut *p });
        if let Some(ref m) = res {
            self.head = m.next;
        }
        res
    }
}
