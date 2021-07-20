use std::convert::TryInto;
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

#[derive(Debug)]
pub enum CallbackMsg<'r> {
    RuleMatching(Rule<'r>),
    RuleNotMatching,
    ScanFinished,
    ImportModule,
    ModuleImported,
    UnknownMsg,
}

impl<'r> CallbackMsg<'r> {
    fn from_yara(context: *mut YR_SCAN_CONTEXT, message: i32, message_data: *mut c_void) -> Self {
        use self::CallbackMsg::*;

        match message as u32 {
            yara_sys::CALLBACK_MSG_RULE_MATCHING => {
                let rule = unsafe { &*(message_data as *mut yara_sys::YR_RULE) };
                let context = unsafe { &*context };
                RuleMatching(Rule::from((context, rule)))
            }
            yara_sys::CALLBACK_MSG_RULE_NOT_MATCHING => RuleNotMatching,
            yara_sys::CALLBACK_MSG_SCAN_FINISHED => ScanFinished,
            yara_sys::CALLBACK_MSG_IMPORT_MODULE => ImportModule,
            yara_sys::CALLBACK_MSG_MODULE_IMPORTED => ModuleImported,
            _ => UnknownMsg,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CallbackReturn {
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
    callback: impl FnMut(CallbackMsg<'a>) -> CallbackReturn,
) -> Result<(), YaraError> {
    let p_callback: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        Box::new(Box::new(callback));
    let user_data = Box::into_raw(p_callback) as *mut c_void;
    let result = unsafe {
        yara_sys::yr_rules_scan_mem(
            rules,
            mem.as_ptr(),
            mem.len().try_into().unwrap(),
            flags,
            Some(scan_callback),
            user_data,
            timeout,
        )
    };
    let _: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        unsafe { Box::from_raw(user_data as *mut _) };

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| ())
}

/// Scan a buffer with the provided YR_SCANNER and its defined external vars.
///
/// Setting the callback function modifies the Scanner with no locks preventing
/// data races, so it should only be called from a &mut Scanner.
pub fn scanner_scan_mem<'a>(
    scanner: *mut yara_sys::YR_SCANNER,
    mem: &[u8],
    callback: impl FnMut(CallbackMsg<'a>) -> CallbackReturn,
) -> Result<(), YaraError> {
    let p_callback: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        Box::new(Box::new(callback));
    let user_data = Box::into_raw(p_callback) as *mut c_void;
    let result = unsafe {
        yara_sys::yr_scanner_set_callback(scanner, Some(scan_callback), user_data);
        yara_sys::yr_scanner_scan_mem(scanner, mem.as_ptr(), mem.len().try_into().unwrap())
    };
    let _: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        unsafe { Box::from_raw(user_data as *mut _) };

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| ())
}

pub fn rules_scan_file<'a>(
    rules: *mut yara_sys::YR_RULES,
    file: &File,
    timeout: i32,
    flags: i32,
    callback: impl FnMut(CallbackMsg<'a>) -> CallbackReturn,
) -> Result<(), YaraError> {
    let result = rules_scan_raw(rules, file, timeout, flags, callback);

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| ())
}

/// Scan a file with the provided YR_SCANNER and its defined external vars.
///
/// Setting the callback function modifies the Scanner with no locks preventing
/// data races, so it should only be called from a &mut Scanner.
pub fn scanner_scan_file<'a>(
    scanner: *mut yara_sys::YR_SCANNER,
    file: &File,
    callback: impl FnMut(CallbackMsg<'a>) -> CallbackReturn,
) -> Result<(), YaraError> {
    let result = scanner_scan_raw(scanner, file, callback);

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| ())
}

#[cfg(unix)]
pub fn rules_scan_raw<'a>(
    rules: *mut yara_sys::YR_RULES,
    file: &File,
    timeout: i32,
    flags: i32,
    callback: impl FnMut(CallbackMsg<'a>) -> CallbackReturn,
) -> i32 {
    let fd = file.as_raw_fd();
    let p_callback: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        Box::new(Box::new(callback));
    let user_data = Box::into_raw(p_callback) as *mut c_void;
    let result = unsafe {
        yara_sys::yr_rules_scan_fd(rules, fd, flags, Some(scan_callback), user_data, timeout)
    };
    let _: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        unsafe { Box::from_raw(user_data as *mut _) };
    result
}

#[cfg(windows)]
pub fn rules_scan_raw<'a>(
    rules: *mut yara_sys::YR_RULES,
    file: &File,
    timeout: i32,
    flags: i32,
    callback: impl FnMut(CallbackMsg<'a>) -> CallbackReturn,
) -> i32 {
    let handle = file.as_raw_handle();
    let p_callback: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        Box::new(Box::new(callback));
    let user_data = Box::into_raw(p_callback) as *mut c_void;

    let result = unsafe {
        yara_sys::yr_rules_scan_fd(
            rules,
            handle,
            flags,
            Some(scan_callback),
            user_data,
            timeout,
        )
    };
    let _: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        unsafe { Box::from_raw(user_data as *mut _) };
    result
}

#[cfg(unix)]
/// Scan a file with the provided YR_SCANNER and its defined external vars.
///
/// Setting the callback function modifies the Scanner with no locks preventing
/// data races, so it should only be called from a &mut Scanner.
pub fn scanner_scan_raw<'a>(
    scanner: *mut yara_sys::YR_SCANNER,
    file: &File,
    callback: impl FnMut(CallbackMsg<'a>) -> CallbackReturn,
) -> i32 {
    let fd = file.as_raw_fd();
    let p_callback: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        Box::new(Box::new(callback));
    let user_data = Box::into_raw(p_callback) as *mut c_void;
    let result = unsafe {
        yara_sys::yr_scanner_set_callback(scanner, Some(scan_callback), user_data);
        yara_sys::yr_scanner_scan_fd(scanner, fd)
    };
    let _: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        unsafe { Box::from_raw(user_data as *mut _) };
    result
}

#[cfg(windows)]
/// Scan a file with the provided YR_SCANNER and its defined external vars.
///
/// Setting the callback function modifies the Scanner with no locks preventing
/// data races, so it should only be called from a &mut Scanner.
pub fn scanner_scan_raw<'a>(
    scanner: *mut yara_sys::YR_SCANNER,
    file: &File,
    callback: impl FnMut(CallbackMsg<'a>) -> CallbackReturn,
) -> i32 {
    let handle = file.as_raw_handle();
    let p_callback: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        Box::new(Box::new(callback));
    let user_data = Box::into_raw(p_callback) as *mut c_void;
    let result = unsafe {
        yara_sys::yr_scanner_set_callback(scanner, Some(scan_callback), user_data);
        yara_sys::yr_scanner_scan_fd(scanner, handle)
    };
    let _: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        unsafe { Box::from_raw(user_data as *mut _) };
    result
}

/// Attach a process, pause it, and scan its memory.
pub fn rules_scan_proc<'a>(
    rules: *mut yara_sys::YR_RULES,
    pid: u32,
    timeout: i32,
    flags: i32,
    callback: impl FnMut(CallbackMsg<'a>) -> CallbackReturn,
) -> Result<(), YaraError> {
    let p_callback: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        Box::new(Box::new(callback));
    let user_data = Box::into_raw(p_callback) as *mut c_void;
    let result = unsafe {
        yara_sys::yr_rules_scan_proc(
            rules,
            pid as i32,
            flags,
            Some(scan_callback),
            user_data,
            timeout,
        )
    };
    let _: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        unsafe { Box::from_raw(user_data as *mut _) };

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| ())
}

/// Attach a process, pause it, and scan its memory with the provided YR_SCANNER
/// and its defined external vars.
///
/// Setting the callback function modifies the Scanner with no locks preventing
/// data races, so it should only be called from a &mut Scanner.
pub fn scanner_scan_proc<'a>(
    scanner: *mut yara_sys::YR_SCANNER,
    pid: u32,
    callback: impl FnMut(CallbackMsg<'a>) -> CallbackReturn,
) -> Result<(), YaraError> {
    let p_callback: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        Box::new(Box::new(callback));
    let user_data = Box::into_raw(p_callback) as *mut c_void;
    let result = unsafe {
        yara_sys::yr_scanner_set_callback(scanner, Some(scan_callback), user_data);
        yara_sys::yr_scanner_scan_proc(scanner, pid as i32)
    };
    let _: Box<Box<dyn FnMut(CallbackMsg<'a>) -> CallbackReturn>> =
        unsafe { Box::from_raw(user_data as *mut _) };

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| ())
}

extern "C" fn scan_callback(
    context: *mut YR_SCAN_CONTEXT,
    message: i32,
    message_data: *mut c_void,
    user_data: *mut c_void,
) -> i32 {
    let message = CallbackMsg::from_yara(context, message, message_data);
    let callback: &mut Box<dyn FnMut(CallbackMsg) -> CallbackReturn> =
        unsafe { std::mem::transmute(user_data) };
    callback(message).to_yara()
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
