use std::ffi::CStr;
use std::fs::File;
use std::mem;
use std::os::raw;

use yara_sys;

use super::{Rule, Rules};

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

#[derive(Debug)]
pub struct Match {

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

#[derive(Default)]
struct ScanResults {
    matches: Vec<()>,
}

pub fn rules_scan_mem(rules: *mut Rules, mem: &[u8], timeout: i32) -> Result<(), YaraError> {
    let mut results = Ok(ScanResults::default());
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
    YaraErrorKind::from_yara(result).map_err(|e| e.into())
        .and(results)
        .map(|_| ()) // TODO Change
}

#[cfg(unix)]
pub fn rules_scan_fd(rules: *mut Rules, file: File, timeout: i32) -> Result<(), Error> {
    use std::os::unix::io::AsRawFd;

    let mut results = Ok(ScanResults::default());
    let fd = file.as_raw_fd();
    let result = unsafe {
        yara_sys::yr_rules_scan_fd(
            rules,
            fd,
            0,
            Some(scan_callback),
            mem::transmute(&mut results),
            timeout,
        )
    };
    YaraErrorKind::from_yara(result).map_err(|e| e.into())
        .and(results)
        .map(|_| ()) // TODO Change
}

extern "C" fn scan_callback(
    message: raw::c_int,
    message_data: *mut raw::c_void,
    user_data: *mut raw::c_void,
) -> i32 {
    let results: &mut Result<ScanResults, Error> = unsafe { mem::transmute(user_data) };
    let message = CallbackMsg::from_yara(message);

    if message == CallbackMsg::RuleMatching {
        let rule: &Rule = unsafe { mem::transmute(message_data) };
        let truc = unsafe { CStr::from_ptr(rule.__bindgen_anon_1.identifier) };
    }

    CallbackReturn::Continue.to_yara()
}
