use std::ffi;

use yara_sys;

use errors::*;

use super::Rules;

pub fn rules_destroy(rules: *mut Rules) {
    unsafe {
        yara_sys::yr_rules_destroy(rules);
    }
}

// TODO Check if non mut
pub fn rules_save(rules: *mut Rules, filename: &str) -> Result<(), YaraError> {
    let filename = ffi::CString::new(filename).unwrap();
    let result = unsafe { yara_sys::yr_rules_save(rules, filename.as_ptr()) };

    YaraErrorKind::from_yara(result)
}
