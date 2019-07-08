use std::fs::File;
use std::os::raw::c_void;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

use yara_sys;

use crate::errors::*;
use crate::Rule;

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
    rules: &mut yara_sys::YR_RULES,
    mem: &[u8],
    timeout: i32,
) -> Result<Vec<Rule<'a>>, YaraError> {
    let mut results = Vec::<Rule<'a>>::new();
    let result = unsafe {
        yara_sys::yr_rules_scan_mem(
            rules,
            mem.as_ptr(),
            mem.len(),
            0,
            Some(scan_callback),
            &mut results as *mut Vec<_> as *mut c_void,
            timeout,
        )
    };

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| results)
}

pub fn rules_scan_file<'a>(
    rules: &mut yara_sys::YR_RULES,
    file: &File,
    timeout: i32,
) -> Result<Vec<Rule<'a>>, YaraError> {
    let mut results = Vec::<Rule<'a>>::new();
    let result = rules_scan_raw(rules, file, timeout, &mut results);

    yara_sys::Error::from_code(result)
        .map_err(|e| e.into())
        .map(|_| results)
}

#[cfg(unix)]
pub fn rules_scan_raw(
    rules: &mut yara_sys::YR_RULES,
    file: &File,
    timeout: i32,
    results: &mut Vec<Rule>,
) -> i32 {
    let fd = file.as_raw_fd();
    unsafe {
        yara_sys::yr_rules_scan_fd(
            rules,
            fd,
            0,
            Some(scan_callback),
            results as *mut Vec<_> as *mut c_void,
            timeout,
        )
    }
}

#[cfg(windows)]
pub fn rules_scan_raw(
    rules: &mut yara_sys::YR_RULES,
    file: &File,
    timeout: i32,
    results: &mut Vec<Rule>,
) -> i32 {
    let handle = file.as_raw_handle();
    unsafe {
        yara_sys::yr_rules_scan_fd(
            rules,
            handle,
            0,
            Some(scan_callback),
            results as *mut Vec<_> as *mut c_void,
            timeout,
        )
    }
}

extern "C" fn scan_callback(
    message: i32,
    message_data: *mut c_void,
    user_data: *mut c_void,
) -> i32 {
    let message = CallbackMsg::from_yara(message);
    let rules = unsafe { &mut *(user_data as *mut Vec<Rule>) };

    if message == CallbackMsg::RuleMatching {
        let rule = unsafe { &*(message_data as *mut yara_sys::YR_RULE) };
        rules.push(Rule::from(rule));
    }

    CallbackReturn::Continue.to_yara()
}
