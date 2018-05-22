#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod errors;

pub use errors::*;

use std::os::raw::c_char;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// TODO: Find a better way than accessing anonymous fields or use flag yara 3.7 or something else.
impl YR_MATCHES {
    pub fn get_head(&self) -> *const _YR_MATCH {
        unsafe { self.__bindgen_anon_1.head }
    }

    pub fn get_tail(&self) -> *const _YR_MATCH {
        unsafe { self.__bindgen_anon_2.tail }
    }
}

impl YR_META {
    pub fn get_identifier(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_1.identifier }
    }

    pub fn get_string(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_2.string }
    }
}

impl YR_NAMESPACE {
    pub fn get_name(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_1.name }
    }
}

impl YR_RULE {

    pub fn get_identifier(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_1.identifier }
    }

    pub fn get_tags(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_2.tags }
    }

    pub fn get_metas(&self) -> *const YR_META {
        unsafe { self.__bindgen_anon_3.metas }
    }

    pub fn get_strings(&self) -> *const YR_STRING {
        unsafe { self.__bindgen_anon_4.strings }
    }

    pub fn get_ns(&self) -> *const YR_NAMESPACE {
        unsafe { self.__bindgen_anon_5.ns }
    }
}

impl YR_STRING {
    pub fn get_identifier(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_1.identifier }
    }

    pub fn get_string(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_2.string as _ }
    }
}
