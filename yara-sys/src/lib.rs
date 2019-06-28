#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod errors;

pub use crate::errors::*;

use std::os::raw::c_char;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetaType {
    Null,
    Integer,
    String,
    Boolean,
}

impl MetaType {
    pub fn from_code(code: i32) -> Result<Self, i32> {
        use self::MetaType::*;
        match code as u32 {
            META_TYPE_NULL => Ok(Null),
            META_TYPE_INTEGER => Ok(Integer),
            META_TYPE_STRING => Ok(String),
            META_TYPE_BOOLEAN => Ok(Boolean),
            _ => Err(code),
        }
    }
}

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
