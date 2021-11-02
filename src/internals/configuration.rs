use std::ffi::c_void;

use crate::errors::*;

/// A `ConfigName` is enum of available configuration options
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigName {
    /// Stack size to use for YR_CONFIG_STACK_SIZE
    StackSize,
    /// Maximum number of strings to allow per yara rule. Will be mapped to YR_CONFIG_MAX_STRINGS_PER_RULE
    MaxStringsPerRule,
    /// Maximum number of bytes to allow per yara match. Will be mapped to YR_CONFIG_MAX_MATCH_DATA
    MaxMatchData,
}

#[cfg(unix)]
type EnumType = u32;
#[cfg(windows)]
type EnumType = i32;

impl ConfigName {
    pub fn to_yara(&self) -> EnumType {
        use self::ConfigName::*;
        let res = match self {
            StackSize => yara_sys::_YR_CONFIG_NAME_YR_CONFIG_STACK_SIZE,
            MaxStringsPerRule => yara_sys::_YR_CONFIG_NAME_YR_CONFIG_MAX_STRINGS_PER_RULE,
            MaxMatchData => yara_sys::_YR_CONFIG_NAME_YR_CONFIG_MAX_MATCH_DATA,
        };
        res as EnumType
    }
}

pub fn set_configuration(name: ConfigName, value: u32) -> Result<(), YaraError> {
    let result = unsafe {
        yara_sys::yr_set_configuration(name.to_yara(), &value as *const u32 as *mut c_void)
    };

    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn get_configuration(name: ConfigName) -> Result<u32, YaraError> {
    let value: u32 = 0;
    let result = unsafe {
        yara_sys::yr_get_configuration(name.to_yara(), &value as *const u32 as *mut c_void)
    };

    yara_sys::Error::from_code(result)
        .map_err(Into::into)
        .map(|_| value)
}
