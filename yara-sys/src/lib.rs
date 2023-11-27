#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub mod errors;

pub use crate::errors::*;

use std::os::raw::c_char;

#[allow(clippy::all)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
pub use bindings::*;

pub mod scan_flags {
    pub use super::{
        SCAN_FLAGS_FAST_MODE, SCAN_FLAGS_NO_TRYCATCH, SCAN_FLAGS_PROCESS_MEMORY,
        SCAN_FLAGS_REPORT_RULES_MATCHING, SCAN_FLAGS_REPORT_RULES_NOT_MATCHING,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetaType {
    Integer,
    String,
    Boolean,
}

impl MetaType {
    #[deny(unused_variables)]
    pub fn from_code(code: i32) -> Result<Self, i32> {
        use self::MetaType::*;
        match code as u32 {
            META_TYPE_INTEGER => Ok(Integer),
            META_TYPE_STRING => Ok(String),
            META_TYPE_BOOLEAN => Ok(Boolean),
            _ => Err(code),
        }
    }
}

impl YR_MATCHES {
    #[deprecated = "Useless now"]
    pub fn get_head(&self) -> *const YR_MATCH {
        self.head
    }

    #[deprecated = "Useless now"]
    pub fn get_tail(&self) -> *const YR_MATCH {
        self.tail
    }
}

// TODO: Find a better way than accessing anonymous fields.
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

impl YR_RULES {
    pub fn get_rules_table(&self) -> *const YR_RULE {
        unsafe { self.__bindgen_anon_1.rules_table }
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

    pub fn enable(&mut self) {
        unsafe {
            yr_rule_enable(self);
        }
    }

    pub fn disable(&mut self) {
        unsafe {
            yr_rule_disable(self);
        }
    }
}

impl YR_STRING {
    pub fn get_identifier(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_3.identifier }
    }

    pub fn get_string(&self) -> *const c_char {
        unsafe { self.__bindgen_anon_1.string as _ }
    }
}
