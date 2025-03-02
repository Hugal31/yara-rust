#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A match within a scan.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Match {
    // base offset of the memory block in which the match occurred.
    pub base: usize,
    /// Offset of the match within the scanning area.
    pub offset: usize,
    /// Length of the file. Can be useful if the matcher string has not a fixed length.
    pub length: usize,
    /// Matched data.
    pub data: Vec<u8>,
    /// Xor key used for the match, if the string is using a xor modifier.
    pub xor_key: u8,
}
