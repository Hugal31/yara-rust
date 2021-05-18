use crate::Match;
use serde::{Serialize, Deserialize};

/// A matcher string that matched during a scan.
#[derive(Debug, Serialize, Deserialize)]
pub struct YrString<'a> {
    /// Name of the string, with the '$'.
    pub identifier: &'a str,
    /// Matches of the string for the scan.
    pub matches: Vec<Match>,
}
