use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt::Debug;

/// A value from a module.
pub struct YrObject<'a>(&'a yara_sys::YR_OBJECT);

impl Debug for YrObject<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt("YrObject", f)
    }
}

impl<'a> From<&'a yara_sys::YR_OBJECT> for YrObject<'a> {
    fn from(value: &'a yara_sys::YR_OBJECT) -> Self {
        Self(value)
    }
}

impl YrObject<'_> {
    /// Get the identifier of the object.
    ///
    /// This is not always set, depending on the object.
    /// For example, objects in [`YrObjectValue::Structure`] have an identifier, but those in
    /// [`YrObjectValue::Array`] do not.
    pub fn identifier(&self) -> Option<&[u8]> {
        let ptr = self.0.identifier;
        if ptr.is_null() {
            None
        } else {
            // Safety:
            // - ptr is not null, and is guaranteed by libyara to be nul-terminated
            // - returned slice is valid for as long as self, guaranteeing the ptr to stay valid.
            let cstr = unsafe { CStr::from_ptr(ptr) };
            Some(cstr.to_bytes())
        }
    }

    /// Get the value of the object.
    pub fn value(&self) -> YrObjectValue {
        unsafe {
            match self.0.type_ as u32 {
                yara_sys::OBJECT_TYPE_INTEGER => {
                    let v = self.0.value.i;
                    if v == yara_sys::YR_UNDEFINED {
                        YrObjectValue::Undefined
                    } else {
                        YrObjectValue::Integer(v)
                    }
                }
                yara_sys::OBJECT_TYPE_FLOAT => {
                    if self.0.value.i == yara_sys::YR_UNDEFINED {
                        YrObjectValue::Undefined
                    } else {
                        YrObjectValue::Float(self.0.value.d)
                    }
                }
                yara_sys::OBJECT_TYPE_STRING => {
                    let p = self.0.value.ss;
                    if p.is_null() {
                        YrObjectValue::Undefined
                    } else {
                        YrObjectValue::String(std::slice::from_raw_parts(
                            (*p).c_string.as_ptr().cast(),
                            (*p).length as usize,
                        ))
                    }
                }
                yara_sys::OBJECT_TYPE_STRUCTURE => {
                    let this: &yara_sys::YR_OBJECT_STRUCTURE = std::mem::transmute(self.0);
                    let mut members = Vec::new();

                    let mut member = this.members;
                    while !member.is_null() {
                        let obj = (*member).object;
                        if !obj.is_null() {
                            members.push(YrObject::from(&*obj));
                        }
                        member = (*member).next;
                    }
                    YrObjectValue::Structure(members)
                }
                yara_sys::OBJECT_TYPE_ARRAY => {
                    let this: &yara_sys::YR_OBJECT_ARRAY = std::mem::transmute(self.0);
                    if this.items.is_null() {
                        return YrObjectValue::Array(Vec::new());
                    }

                    let objects = std::slice::from_raw_parts(
                        (*this.items).objects.as_ptr(),
                        (*this.items).length as usize,
                    );

                    YrObjectValue::Array(
                        objects
                            .iter()
                            .map(|v| {
                                if v.is_null() {
                                    None
                                } else {
                                    Some(YrObject::from(&**v))
                                }
                            })
                            .collect(),
                    )
                }
                yara_sys::OBJECT_TYPE_DICTIONARY => {
                    let this: &yara_sys::YR_OBJECT_DICTIONARY = std::mem::transmute(self.0);
                    if this.items.is_null() {
                        return YrObjectValue::Dictionary(HashMap::new());
                    }

                    let objects = std::slice::from_raw_parts(
                        (*this.items).objects.as_ptr(),
                        (*this.items).used as usize,
                    );

                    YrObjectValue::Dictionary(
                        objects
                            .iter()
                            .filter_map(|v| {
                                if v.key.is_null() || v.obj.is_null() {
                                    return None;
                                }

                                let key = std::slice::from_raw_parts(
                                    (*v.key).c_string.as_ptr().cast(),
                                    (*v.key).length as usize,
                                );
                                Some((key, YrObject::from(&*v.obj)))
                            })
                            .collect(),
                    )
                }
                yara_sys::OBJECT_TYPE_FUNCTION => YrObjectValue::Function,
                _ => YrObjectValue::Undefined,
            }
        }
    }
}

/// A value stored in a [`YrObject`].
#[derive(Debug)]
pub enum YrObjectValue<'a> {
    Integer(i64),
    Float(f64),
    String(&'a [u8]),
    Array(Vec<Option<YrObject<'a>>>),
    Dictionary(HashMap<&'a [u8], YrObject<'a>>),
    Structure(Vec<YrObject<'a>>),
    Function,
    Undefined,
}
