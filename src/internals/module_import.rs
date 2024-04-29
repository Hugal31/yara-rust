use std::ffi::{c_void, CStr};
use std::fmt::Debug;

/// Details about a module being imported.
pub struct YrModuleImport<'a>(&'a mut yara_sys::YR_MODULE_IMPORT);

impl Debug for YrModuleImport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt("YrModuleImport", f)
    }
}

impl<'a> From<&'a mut yara_sys::YR_MODULE_IMPORT> for YrModuleImport<'a> {
    fn from(value: &'a mut yara_sys::YR_MODULE_IMPORT) -> Self {
        Self(value)
    }
}

impl YrModuleImport<'_> {
    /// Get the name of the module.
    pub fn name(&self) -> Option<&[u8]> {
        let ptr = self.0.module_name;
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

    /// Set the module data to be used by the module.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that:
    /// - `ptr` is valid for reads of `size` bytes.
    /// - `ptr` stays valid for the full duration of the scan.
    pub unsafe fn set_module_data(&mut self, ptr: *mut c_void, size: usize) {
        self.0.module_data = ptr;
        self.0.module_data_size = size as _;
    }
}
