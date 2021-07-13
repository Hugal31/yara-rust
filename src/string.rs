use crate::Match;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A matcher string that matched during a scan.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct YrString<'a> {
    /// Name of the string, with the '$'.
    pub identifier: &'a str,
    /// Matches of the string for the scan.
    pub matches: Vec<Match>,
}
