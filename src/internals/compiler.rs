use std::convert::Into;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::os::raw::{c_char, c_int, c_void};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use yara_sys::{YR_COMPILER, YR_RULE, YR_RULES};

use crate::errors::*;

pub fn compiler_create<'a>() -> Result<&'a mut YR_COMPILER, YaraError> {
    let mut pointer: *mut YR_COMPILER = ptr::null_mut();
    let result = unsafe { yara_sys::yr_compiler_create(&mut pointer) };

    yara_sys::Error::from_code(result)
        .map(|()| unsafe { &mut *pointer })
        .map_err(|e| e.into())
}

pub fn compiler_destroy(compiler_ptr: *mut YR_COMPILER) {
    unsafe {
        yara_sys::yr_compiler_destroy(compiler_ptr);
    }
}

pub fn compiler_add_string<T: Into<Vec<u8>>>(
    compiler: *mut YR_COMPILER,
    rule: T,
    namespace: Option<&str>,
) -> Result<(), Error> {
    let rule = CString::new(rule).unwrap();
    let namespace = namespace.map(|n| CString::new(n).unwrap());
    let mut errors = Vec::<CompileError>::new();
    unsafe {
        yara_sys::yr_compiler_set_callback(
            compiler,
            Some(compile_callback),
            &mut errors as *mut Vec<_> as _,
        )
    };
    let result = unsafe {
        yara_sys::yr_compiler_add_string(
            compiler,
            rule.as_ptr(),
            namespace.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
        )
    };

    compile_result(result, errors)
}

pub fn compiler_add_file<P: AsRef<Path>>(
    compiler: *mut YR_COMPILER,
    file: &File,
    path: P,
    namespace: Option<&str>,
) -> Result<(), Error> {
    // TODO: Improve. WTF.
    let path = CString::new(path.as_ref().as_os_str().to_str().unwrap()).unwrap();
    let namespace = namespace.map(|n| CString::new(n).unwrap());
    let mut errors = Vec::<CompileError>::new();
    unsafe {
        yara_sys::yr_compiler_set_callback(
            compiler,
            Some(compile_callback),
            &mut errors as *mut Vec<_> as _,
        )
    };
    let result = compiler_add_file_raw(compiler, file, &path, namespace.as_deref());

    compile_result(result, errors)
}

fn compile_result(compile_result: i32, messages: Vec<CompileError>) -> Result<(), Error> {
    if compile_result == 0 || messages.iter().all(|c| c.level != CompileErrorLevel::Error) {
        Ok(())
    } else {
        Err(CompileErrors::new(messages).into())
    }
}

#[cfg(unix)]
fn compiler_add_file_raw(
    compiler: *mut YR_COMPILER,
    file: &File,
    path: &CStr,
    namespace: Option<&CStr>,
) -> i32 {
    let fd = file.as_raw_fd();
    unsafe {
        yara_sys::yr_compiler_add_fd(
            compiler,
            fd,
            namespace.map_or(ptr::null(), CStr::as_ptr),
            path.as_ptr(),
        )
    }
}

#[cfg(windows)]
fn compiler_add_file_raw(
    compiler: *mut YR_COMPILER,
    file: &File,
    path: &CStr,
    namespace: Option<&CStr>,
) -> i32 {
    let handle = file.as_raw_handle();
    unsafe {
        yara_sys::yr_compiler_add_fd(
            compiler,
            handle,
            namespace.map_or(ptr::null(), |s| s.as_ptr()),
            path.as_ptr(),
        )
    }
}

extern "C" fn compile_callback(
    error_level: c_int,
    filename: *const c_char,
    line_number: c_int,
    _rule: *const YR_RULE,
    message: *const c_char,
    user_data: *mut c_void,
) {
    let errors: &mut Vec<CompileError> = unsafe { &mut *(user_data as *mut Vec<CompileError>) };
    let message = unsafe { CStr::from_ptr(message) }.to_str().unwrap();
    let filename = if !filename.is_null() {
        Some(unsafe { CStr::from_ptr(filename) }.to_str().unwrap())
    } else {
        None
    };
    errors.push(CompileError {
        level: CompileErrorLevel::from_code(error_level),
        filename: filename.map(|s| s.to_string()),
        line: line_number as usize,
        message: message.to_owned(),
    });
}

pub fn compiler_define_integer_variable(
    compiler: *mut YR_COMPILER,
    identifier: &str,
    value: i64,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let result = unsafe {
        yara_sys::yr_compiler_define_integer_variable(compiler, identifier.as_ptr(), value)
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn compiler_define_float_variable(
    compiler: *mut YR_COMPILER,
    identifier: &str,
    value: f64,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let result = unsafe {
        yara_sys::yr_compiler_define_float_variable(compiler, identifier.as_ptr(), value)
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn compiler_define_boolean_variable(
    compiler: *mut YR_COMPILER,
    identifier: &str,
    value: bool,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let value = if value { 1 } else { 0 };
    let result = unsafe {
        yara_sys::yr_compiler_define_boolean_variable(compiler, identifier.as_ptr(), value)
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn compiler_define_str_variable(
    compiler: *mut YR_COMPILER,
    identifier: &str,
    value: &str,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let value = CString::new(value).unwrap();
    let result = unsafe {
        yara_sys::yr_compiler_define_string_variable(compiler, identifier.as_ptr(), value.as_ptr())
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn compiler_define_cstr_variable(
    compiler: *mut YR_COMPILER,
    identifier: &str,
    value: &CStr,
) -> Result<(), YaraError> {
    let identifier = CString::new(identifier).unwrap();
    let result = unsafe {
        yara_sys::yr_compiler_define_string_variable(compiler, identifier.as_ptr(), value.as_ptr())
    };
    yara_sys::Error::from_code(result).map_err(Into::into)
}

pub fn compiler_get_rules(compiler: *mut YR_COMPILER) -> Result<*mut YR_RULES, YaraError> {
    let mut pointer = ptr::null_mut();
    let result = unsafe { yara_sys::yr_compiler_get_rules(compiler, &mut pointer) };

    yara_sys::Error::from_code(result)
        .map(|()| pointer)
        .map_err(Into::into)
}
