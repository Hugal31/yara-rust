use std::ffi;
use std::ptr;

use yara_sys;

use errors::*;

use super::{Compiler, Rules};

pub fn compiler_create() -> Result<*mut Compiler, YaraError> {
    let mut pointer: *mut Compiler = ptr::null_mut();
    let result = unsafe { yara_sys::yr_compiler_create(&mut pointer) };

    YaraErrorKind::from_yara(result).map(|()| pointer)
}

pub fn compiler_destroy(compiler_ptr: *mut Compiler) {
    unsafe {
        yara_sys::yr_compiler_destroy(compiler_ptr);
    }
}

pub fn compiler_add_string(
    compiler_ptr: *mut Compiler,
    string: &str,
    namespace: Option<&str>,
) -> Result<(), CompilationError> {
    let string = ffi::CString::new(string).unwrap();
    let namespace = namespace.map(|n| ffi::CString::new(n).unwrap());
    let result = unsafe {
        yara_sys::yr_compiler_add_string(
            compiler_ptr,
            string.as_ptr(),
            namespace.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
        )
    };

    // TODO Add callbacks to get better errors
    if result == 0 {
        Ok(())
    } else {
        Err(CompilationError())
    }
}

pub fn compiler_get_rules(compiler_ptr: *mut Compiler) -> Result<*mut Rules, YaraError> {
    let mut pointer = ptr::null_mut();
    let result = unsafe { yara_sys::yr_compiler_get_rules(compiler_ptr, &mut pointer) };

    YaraErrorKind::from_yara(result).map(|()| pointer)
}
