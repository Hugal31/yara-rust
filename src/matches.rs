/// A match within a scan.
use serde::{Serialize, Deserialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct Match {
    /// Offset of the match within the scanning area.
    pub offset: usize,
    /// Length of the file. Can be useful if the matcher string has not a fixed length.
    pub length: usize,
    /// Matched data.
    pub data: Vec<u8>,
}
