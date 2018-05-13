use std::ffi;
use std::mem;
use std::ptr;

use yara_sys;
use yara_sys::{YR_COMPILER, YR_RULES};

use errors::*;

pub fn compiler_create<'a>() -> Result<&'a mut YR_COMPILER, YaraError> {
    let mut pointer: *mut YR_COMPILER = ptr::null_mut();
    let result = unsafe { yara_sys::yr_compiler_create(&mut pointer) };

    yara_sys::Error::from_code(result)
        .map(|()| unsafe { mem::transmute(pointer) })
        .map_err(|e| e.into())
}

pub fn compiler_destroy(compiler_ptr: *mut YR_COMPILER) {
    unsafe {
        yara_sys::yr_compiler_destroy(compiler_ptr);
    }
}

pub fn compiler_add_string(
    compiler: &mut YR_COMPILER,
    string: &str,
    namespace: Option<&str>,
) -> Result<(), YaraError> {
    let string = ffi::CString::new(string).unwrap();
    let namespace = namespace.map(|n| ffi::CString::new(n).unwrap());
    let result = unsafe {
        yara_sys::yr_compiler_add_string(
            compiler,
            string.as_ptr(),
            namespace.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
        )
    };

    // TODO Add callbacks to get better errors
    if result == 0 {
        Ok(())
    } else {
        Err(yara_sys::Error::SyntaxError.into())
    }
}

pub fn compiler_get_rules(compiler: &mut YR_COMPILER) -> Result<&mut YR_RULES, YaraError> {
    let mut pointer = ptr::null_mut();
    let result = unsafe { yara_sys::yr_compiler_get_rules(compiler, &mut pointer) };

    yara_sys::Error::from_code(result)
        .map(|()| unsafe { mem::transmute(pointer) })
        .map_err(|e| e.into())
}
