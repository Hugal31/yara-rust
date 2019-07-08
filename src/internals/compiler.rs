use std::ffi::{CStr, CString};
use std::fs::File;
use std::ops::Deref;
use std::os::raw::{c_char, c_int, c_void};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use yara_sys;
use yara_sys::{YR_COMPILER, YR_RULES};

use crate::errors::*;

pub fn compiler_create<'a>() -> Result<&'a mut YR_COMPILER, YaraError> {
    let mut pointer: *mut YR_COMPILER = ptr::null_mut();
    let result = unsafe { yara_sys::yr_compiler_create(&mut pointer) };

    yara_sys::Error::from_code(result)
        .map(|()| unsafe { &mut *pointer })
        .map_err(|e| e.into())
}

pub fn compiler_destroy(compiler_ptr: &mut YR_COMPILER) {
    unsafe {
        yara_sys::yr_compiler_destroy(compiler_ptr);
    }
}

pub fn compiler_add_string(
    compiler: &mut YR_COMPILER,
    string: &str,
    namespace: Option<&str>,
) -> Result<(), Error> {
    let string = CString::new(string).unwrap();
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
            string.as_ptr(),
            namespace.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(CompileErrors::new(errors).into())
    }
}

pub fn compiler_add_file<P: AsRef<Path>>(
    compiler: &mut YR_COMPILER,
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
    let result =
        compiler_add_file_raw(compiler, file, &path, namespace.as_ref().map(|e| e.deref()));

    if result == 0 {
        Ok(())
    } else {
        Err(CompileErrors::new(errors).into())
    }
}

#[cfg(unix)]
fn compiler_add_file_raw(
    compiler: &mut YR_COMPILER,
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
    compiler: &mut YR_COMPILER,
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

pub fn compiler_get_rules<'c, 'y: 'c>(
    compiler: &'c mut YR_COMPILER,
) -> Result<&'y mut YR_RULES, YaraError> {
    let mut pointer = ptr::null_mut();
    let result = unsafe { yara_sys::yr_compiler_get_rules(compiler, &mut pointer) };

    yara_sys::Error::from_code(result)
        .map(|()| unsafe { &mut *pointer })
        .map_err(Into::into)
}
