use bitflags::bitflags;
use yara_sys::{
    SCAN_FLAGS_FAST_MODE, SCAN_FLAGS_NO_TRYCATCH, SCAN_FLAGS_REPORT_RULES_MATCHING,
    SCAN_FLAGS_REPORT_RULES_NOT_MATCHING,
};

bitflags! {
    /// A wrapper around yara scanning flags
    #[derive(Default, Debug, Clone, Copy, Eq, PartialEq)]
    pub struct ScanFlags: i32 {
        /// SCAN_FLAGS_FAST_MODE
        const FAST_MODE = SCAN_FLAGS_FAST_MODE as i32;
        ///  SCAN_FLAGS_NO_TRYCATCH
        const NO_TRYCATCH = SCAN_FLAGS_NO_TRYCATCH as i32;
        /// SCAN_FLAGS_REPORT_RULES_MATCHING
        const REPORT_RULES_MATCHING = SCAN_FLAGS_REPORT_RULES_MATCHING as i32;
        /// SCAN_FLAGS_REPORT_RULES_NOT_MATCHING
        const REPORT_RULES_NOT_MATCHING = SCAN_FLAGS_REPORT_RULES_NOT_MATCHING as i32;
    }
}
