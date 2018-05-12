use std::ffi;
use std::mem;
use std::ptr;

use yara_sys;
use yara_sys::{YR_COMPILER, YR_RULES};

use errors::*;

pub fn compiler_create<'a>() -> Result<&'a mut YR_COMPILER, YaraError> {
    let mut pointer: *mut YR_COMPILER = ptr::null_mut();
    let result = unsafe { yara_sys::yr_compiler_create(&mut pointer) };

    YaraErrorKind::from_yara(result).map(|()| unsafe { mem::transmute(pointer) })
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
) -> Result<(), CompilationError> {
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
        Err(CompilationError())
    }
}

pub fn compiler_get_rules(compiler: &mut YR_COMPILER) -> Result<&mut YR_RULES, YaraError> {
    let mut pointer = ptr::null_mut();
    let result = unsafe { yara_sys::yr_compiler_get_rules(compiler, &mut pointer) };

    YaraErrorKind::from_yara(result).map(|()| unsafe { mem::transmute(pointer) })
}
