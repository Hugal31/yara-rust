use crate::errors::*;

/// Set the stack size to use.
///
/// This is mapped to the YR_CONFIG_STACK_SIZE property.
pub fn set_stack_size(value: u32) -> Result<(), YaraError> {
    set_cfg_u32(yara_sys::_YR_CONFIG_NAME_YR_CONFIG_STACK_SIZE, value)
}

/// Set the maximum number of strings to allow per yara rule.
///
/// This is mapped to the YR_CONFIG_MAX_STRINGS_PER_RULE property.
pub fn set_max_strings_per_rule(value: u32) -> Result<(), YaraError> {
    set_cfg_u32(
        yara_sys::_YR_CONFIG_NAME_YR_CONFIG_MAX_STRINGS_PER_RULE,
        value,
    )
}

/// Set the maximum number of bytes to allow per yara match.
///
/// This is mapped to the YR_CONFIG_MAX_MATCH_DATA property.
pub fn set_max_match_data(value: u32) -> Result<(), YaraError> {
    set_cfg_u32(yara_sys::_YR_CONFIG_NAME_YR_CONFIG_MAX_MATCH_DATA, value)
}

/// Set the maximum size of chunks scanned from a process memory.
///
/// This is mapped to the YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK property.
pub fn set_max_process_memory_chunk(value: u64) -> Result<(), YaraError> {
    set_cfg_u64(
        yara_sys::_YR_CONFIG_NAME_YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK,
        value,
    )
}

/// Get the stack size.
///
/// This is mapped to the YR_CONFIG_STACK_SIZE property.
pub fn get_stack_size() -> Result<u32, YaraError> {
    get_cfg_u32(yara_sys::_YR_CONFIG_NAME_YR_CONFIG_STACK_SIZE)
}

/// Get the maximum number of strings to allow per yara rule.
///
/// This is mapped to the YR_CONFIG_MAX_STRINGS_PER_RULE property.
pub fn get_max_strings_per_rule() -> Result<u32, YaraError> {
    get_cfg_u32(yara_sys::_YR_CONFIG_NAME_YR_CONFIG_MAX_STRINGS_PER_RULE)
}

/// Get the maximum number of bytes to allow per yara match.
///
/// This is mapped to the YR_CONFIG_MAX_MATCH_DATA property.
pub fn get_max_match_data() -> Result<u32, YaraError> {
    get_cfg_u32(yara_sys::_YR_CONFIG_NAME_YR_CONFIG_MAX_MATCH_DATA)
}

/// Get the maximum size of chunks scanned from a process memory.
///
/// This is mapped to the YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK property.
pub fn get_max_process_memory_chunk() -> Result<u64, YaraError> {
    get_cfg_u64(yara_sys::_YR_CONFIG_NAME_YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK)
}

fn set_cfg_u32(cfg: yara_sys::_YR_CONFIG_NAME, value: u32) -> Result<(), YaraError> {
    let result = unsafe { yara_sys::yr_set_configuration_uint32(cfg, value) };

    yara_sys::Error::from_code(result).map_err(Into::into)
}

fn set_cfg_u64(cfg: yara_sys::_YR_CONFIG_NAME, value: u64) -> Result<(), YaraError> {
    let result = unsafe { yara_sys::yr_set_configuration_uint64(cfg, value) };

    yara_sys::Error::from_code(result).map_err(Into::into)
}

fn get_cfg_u32(cfg: yara_sys::_YR_CONFIG_NAME) -> Result<u32, YaraError> {
    let mut value = 0;

    let result = unsafe { yara_sys::yr_get_configuration_uint32(cfg, &mut value) };

    yara_sys::Error::from_code(result)
        .map(|()| value)
        .map_err(Into::into)
}

fn get_cfg_u64(cfg: yara_sys::_YR_CONFIG_NAME) -> Result<u64, YaraError> {
    let mut value = 0;

    let result = unsafe { yara_sys::yr_get_configuration_uint64(cfg, &mut value) };

    yara_sys::Error::from_code(result)
        .map(|()| value)
        .map_err(Into::into)
}
