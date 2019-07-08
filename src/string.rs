use crate::Match;

/// A matcher string that matched during a scan.
#[derive(Debug)]
pub struct YrString<'a> {
    /// Name of the string, with the '$'.
    pub identifier: &'a str,
    /// Matches of the string for the scan.
    pub matches: Vec<Match>,
}
