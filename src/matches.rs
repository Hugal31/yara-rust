#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A match within a scan.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Match {
    /// Offset of the match within the scanning area.
    pub offset: usize,
    /// Length of the file. Can be useful if the matcher string has not a fixed length.
    pub length: usize,
    /// Matched data.
    pub data: Vec<u8>,
}
