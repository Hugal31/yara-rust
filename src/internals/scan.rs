use std::ffi::{CStr, CString};
use std::fs::File;
use std::os::raw::c_void;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use yara_sys::{YR_SCANNER, YR_SCAN_CONTEXT};

use crate::errors::*;
use crate::Rule;
use std::convert::TryInto;

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
    #[allow(dead_code)]
    Abort,
    #[allow(dead_code)]
    Error,
}

impl CallbackReturn {
    pub fn to_yara(self) -> i32 {
        use self::CallbackReturn::*;

        let res = match self {
            Continue => yara_sys::CALLBACK_CONTINUE,
            Abort => yara_sys::CALLBACK_ABORT,
            Error => yara_sys::CALLBACK_ERROR,
        };
        res as i32
    }
}

pub fn rules_scan_mem<'a>(
    rules: *mut yara_sys::YR_RULES,
    mem: &[u8],
    timeout: i32,
    flags: i32,
) -> Result<Vec<Rule<'a>>, YaraError> {
    let mut results = Vec::<Rule<'a>>::new();
    let result = unsafe {
        yara_sys::yr_rules_scan_mem(
            rules,
            mem.as_ptr(),
            mem.len().try_into().unwrap(),
            flags,
            Some(scan_callback),
            &mut results as *mut Vec<_> as *mut c_void,
            timeout,
        )
    };

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| results)
}

/// Scan a buffer with the provided YR_SCANNER and its defined external vars.
///
/// Setting the callback function modifies the Scanner with no locks preventing
/// data races, so it should only be called from a &mut Scanner.
pub fn scanner_scan_mem<'a>(
    scanner: *mut yara_sys::YR_SCANNER,
    mem: &[u8],
) -> Result<Vec<Rule<'a>>, YaraError> {
    let mut results = Vec::<Rule<'a>>::new();
    let result = unsafe {
        yara_sys::yr_scanner_set_callback(
            scanner,
            Some(scan_callback),
            &mut results as *mut Vec<_> as *mut c_void,
        );
        yara_sys::yr_scanner_scan_mem(scanner, mem.as_ptr(), mem.len().try_into().unwrap())
    };

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| results)
}

pub fn rules_scan_file<'a>(
    rules: *mut yara_sys::YR_RULES,
    file: &File,
    timeout: i32,
    flags: i32,
) -> Result<Vec<Rule<'a>>, YaraError> {
    let mut results = Vec::<Rule<'a>>::new();
    let result = rules_scan_raw(rules, file, timeout, flags, &mut results);

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| results)
}

/// Scan a file with the provided YR_SCANNER and its defined external vars.
///
/// Setting the callback function modifies the Scanner with no locks preventing
/// data races, so it should only be called from a &mut Scanner.
pub fn scanner_scan_file<'a>(
    scanner: *mut yara_sys::YR_SCANNER,
    file: &File,
) -> Result<Vec<Rule<'a>>, YaraError> {
    let mut results = Vec::<Rule<'a>>::new();
    let result = scanner_scan_raw(scanner, file, &mut results);

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| results)
}

#[cfg(unix)]
pub fn rules_scan_raw(
    rules: *mut yara_sys::YR_RULES,
    file: &File,
    timeout: i32,
    flags: i32,
    results: &mut Vec<Rule>,
) -> i32 {
    let fd = file.as_raw_fd();
    unsafe {
        yara_sys::yr_rules_scan_fd(
            rules,
            fd,
            flags,
            Some(scan_callback),
            results as *mut Vec<_> as *mut c_void,
            timeout,
        )
    }
}

#[cfg(windows)]
pub fn rules_scan_raw(
    rules: *mut yara_sys::YR_RULES,
    file: &File,
    timeout: i32,
    flags: i32,
    results: &mut Vec<Rule>,
) -> i32 {
    let handle = file.as_raw_handle();
    unsafe {
        yara_sys::yr_rules_scan_fd(
            rules,
            handle,
            flags,
            Some(scan_callback),
            results as *mut Vec<_> as *mut c_void,
            timeout,
        )
    }
}

#[cfg(unix)]
/// Scan a file with the provided YR_SCANNER and its defined external vars.
///
/// Setting the callback function modifies the Scanner with no locks preventing
/// data races, so it should only be called from a &mut Scanner.
pub fn scanner_scan_raw<'a>(
    scanner: *mut yara_sys::YR_SCANNER,
    file: &File,
    results: &mut Vec<Rule>,
) -> i32 {
    let fd = file.as_raw_fd();
    unsafe {
        yara_sys::yr_scanner_set_callback(
            scanner,
            Some(scan_callback),
            results as *mut Vec<_> as *mut c_void,
        );
        yara_sys::yr_scanner_scan_fd(scanner, fd)
    }
}

#[cfg(windows)]
/// Scan a file with the provided YR_SCANNER and its defined external vars.
///
/// Setting the callback function modifies the Scanner with no locks preventing
/// data races, so it should only be called from a &mut Scanner.
pub fn scanner_scan_raw<'a>(
    scanner: *mut yara_sys::YR_SCANNER,
    file: &File,
    results: &mut Vec<Rule>,
) -> i32 {
    let handle = file.as_raw_handle();
    unsafe {
        yara_sys::yr_scanner_set_callback(
            scanner,
            Some(scan_callback),
            results as *mut Vec<_> as *mut c_void,
        );
        yara_sys::yr_scanner_scan_fd(scanner, handle)
    }
}

extern "C" fn scan_callback(
    context: *mut YR_SCAN_CONTEXT,
    message: i32,
    message_data: *mut c_void,
    user_data: *mut c_void,
) -> i32 {
    let message = CallbackMsg::from_yara(message);
    let rules = unsafe { &mut *(user_data as *mut Vec<Rule>) };

    if message == CallbackMsg::RuleMatching {
        let rule = unsafe { &*(message_data as *mut yara_sys::YR_RULE) };
        let context = unsafe { &*context };
        rules.push(Rule::from((context, rule)));
    }

    CallbackReturn::Continue.to_yara()
}

/// Setting the flags modifies the Scanner with no locks preventing data races,
/// so it should only be called from a &mut Scanner.
pub fn scanner_set_flags<'a>(scanner: *mut yara_sys::YR_SCANNER, flags: i32) {
    unsafe {
        yara_sys::yr_scanner_set_flags(scanner, flags);
    }
}

/// Setting the timeout modifies the Scanner with no locks preventing data races,
/// so it should only be called from a &mut Scanner.
pub fn scanner_set_timeout<'a>(scanner: *mut yara_sys::YR_SCANNER, seconds: i32) {
    unsafe {
        yara_sys::yr_scanner_set_timeout(scanner, seconds);
    }
}

pub fn scanner_define_integer_variable(
    scanner: *mut YR_SCANNER,
    identifier: &str,
    value: i64,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let result = unsafe {
        yara_sys::yr_scanner_define_integer_variable(scanner, identifier.as_ptr(), value)
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn scanner_define_boolean_variable(
    scanner: *mut YR_SCANNER,
    identifier: &str,
    value: bool,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let value = if value { 1 } else { 0 };
    let result = unsafe {
        yara_sys::yr_scanner_define_boolean_variable(scanner, identifier.as_ptr(), value)
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn scanner_define_float_variable(
    scanner: *mut YR_SCANNER,
    identifier: &str,
    value: f64,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let result =
        unsafe { yara_sys::yr_scanner_define_float_variable(scanner, identifier.as_ptr(), value) };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn scanner_define_str_variable(
    scanner: *mut YR_SCANNER,
    identifier: &str,
    value: &str,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let value = CString::new(value).unwrap();
    let result = unsafe {
        yara_sys::yr_scanner_define_string_variable(scanner, identifier.as_ptr(), value.as_ptr())
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn scanner_define_cstr_variable(
    scanner: *mut YR_SCANNER,
    identifier: &str,
    value: &CStr,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let result = unsafe {
        yara_sys::yr_scanner_define_string_variable(scanner, identifier.as_ptr(), value.as_ptr())
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}
