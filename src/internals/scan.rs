use std::os::raw::c_void;

use yara_sys;

use Rule;

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
    #[allow(dead_code)]
    Abort,
    #[allow(dead_code)]
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

pub fn rules_scan_mem<'a>(
    rules: *mut yara_sys::YR_RULES,
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
