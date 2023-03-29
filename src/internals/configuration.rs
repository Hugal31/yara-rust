use std::ffi::c_void;

use crate::errors::*;

/// Set the stack size to use.
///
/// This is mapped to the YR_CONFIG_STACK_SIZE property.
pub fn set_stack_size(value: u32) -> Result<(), YaraError> {
    unsafe {
        set_cfg(
            yara_sys::_YR_CONFIG_NAME_YR_CONFIG_STACK_SIZE,
            &value as *const u32 as *mut c_void,
        )
    }
}

/// Set the maximum number of strings to allow per yara rule.
///
/// This is mapped to the YR_CONFIG_MAX_STRINGS_PER_RULE property.
pub fn set_max_strings_per_rule(value: u32) -> Result<(), YaraError> {
    unsafe {
        set_cfg(
            yara_sys::_YR_CONFIG_NAME_YR_CONFIG_MAX_STRINGS_PER_RULE,
            &value as *const u32 as *mut c_void,
        )
    }
}

/// Set the maximum number of bytes to allow per yara match.
///
/// This is mapped to the YR_CONFIG_MAX_MATCH_DATA property.
pub fn set_max_match_data(value: u32) -> Result<(), YaraError> {
    unsafe {
        set_cfg(
            yara_sys::_YR_CONFIG_NAME_YR_CONFIG_MAX_MATCH_DATA,
            &value as *const u32 as *mut c_void,
        )
    }
}

/// Get the stack size.
///
/// This is mapped to the YR_CONFIG_STACK_SIZE property.
pub fn get_stack_size() -> Result<u32, YaraError> {
    unsafe { get_cfg(yara_sys::_YR_CONFIG_NAME_YR_CONFIG_STACK_SIZE) }
}

/// Get the maximum number of strings to allow per yara rule.
///
/// This is mapped to the YR_CONFIG_MAX_STRINGS_PER_RULE property.
pub fn get_max_strings_per_rule() -> Result<u32, YaraError> {
    unsafe { get_cfg(yara_sys::_YR_CONFIG_NAME_YR_CONFIG_MAX_STRINGS_PER_RULE) }
}

/// Get the maximum number of bytes to allow per yara match.
///
/// This is mapped to the YR_CONFIG_MAX_MATCH_DATA property.
pub fn get_max_match_data() -> Result<u32, YaraError> {
    unsafe { get_cfg(yara_sys::_YR_CONFIG_NAME_YR_CONFIG_MAX_MATCH_DATA) }
}

/// Safety:
///
/// The value pointer must point to a value of the right size for the given config.
unsafe fn set_cfg(cfg: yara_sys::_YR_CONFIG_NAME, value: *mut c_void) -> Result<(), YaraError> {
    let result = unsafe { yara_sys::yr_set_configuration(cfg, value) };

    yara_sys::Error::from_code(result).map_err(Into::into)
}

/// Safety:
///
/// The size of the generic value must match the given config.
unsafe fn get_cfg<T: Default>(cfg: yara_sys::_YR_CONFIG_NAME) -> Result<T, YaraError> {
    let mut value = T::default();

    let result =
        unsafe { yara_sys::yr_get_configuration(cfg, &mut value as *mut T as *mut c_void) };

    yara_sys::Error::from_code(result)
        .map(|()| value)
        .map_err(Into::into)
}
