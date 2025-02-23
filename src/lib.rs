//! Yara rust safe bindings
//!
//! This crate contains safe bindings to
//! [VirusTotal's Yara library][Yara-site],
//! "the pattern matching swiss-knife".
//!
//! I can be used to scan file and memory, with powerful rules statement.
//! It is often used to recognize malwares.
//!
//! This example shows how to write and use a pair of rules to check if a file is an APK,
//! from the [polydet project][polydet]:
//!
//! ```no_run
//! # use yara::{Compiler, Error};
//! let rules = r#"
//! // Search for the ZIP EOCD magic anywhere in the file except the 22 last bytes.
//! rule IsZIP {
//!   strings:
//!     $EOCD_magic = { 50 4B 05 06 }
//!   condition:
//!     $EOCD_magic in (0..filesize - 22)
//! }
//! // Search the ZIP's LFH magic followed by 26 bytes then "AndroidManifest.xml", anywhere in zip files.
//! rule IsAPK {
//!   strings:
//!     //                    P  K             A  n  d  r  o  i  d  M  a  n  i  f  e  s  t  .  x  m  l
//!     $lfh_and_android = { 50 4B 03 04 [26] 41 6E 64 72 6F 69 64 4D 61 6e 69 66 65 73 74 2E 78 6D 6C}
//!
//!   condition:
//!     IsZIP and $lfh_and_android
//! }
//! "#;
//!
//! let mut compiler = Compiler::new()?
//!     .add_rules_str(rules)?;
//! let rules = compiler.compile_rules()?;
//! let results = rules.scan_file("File.apk", 5)?;
//!
//! assert!(results.iter().any(|rule| rule.identifier == "IsAPK"));
//! # Ok::<(), yara::Error>(())
//! ```
//! Learn how to write rules on the [Yara documentation][Yara-doc].
//!
//! [Yara-site]: http://virustotal.github.io/yara/
//! [Yara-doc]: https://yara.readthedocs.io/en/stable/gettingstarted.html
//! [polydet]: https://github.com/Polydet/polydet/

use internals::configuration;
pub use internals::{YrObject, YrObjectValue};

pub use crate::compiler::{Compiler, CompilerVariableValue};
pub use crate::errors::*;
pub use crate::flags::ScanFlags;
use crate::initialize::InitializationToken;
pub use crate::matches::Match;
pub use crate::rules::{Metadata, MetadataValue, Rule, Rules, RulesetRule};
pub use crate::scanner::Scanner;
pub use crate::string::YrString;
pub use internals::{
    CallbackMsg, CallbackReturn, MemoryBlock, MemoryBlockIterator, MemoryBlockIteratorSized,
};

mod compiler;
mod initialize;
mod internals;
mod matches;
mod rules;
mod scanner;
mod string;

pub mod errors;
mod flags;

/// Yara initialization token.
///
/// Act as an initialization token to keep the library initialized.
/// Not mandatory, but can reduce initialization overhead when creating and destroying Yara objects:
/// The library is initialized each time a new object is created, unless it is already initialized.
/// When the last `Yara` object is destroyed, the library is de-initialized.
///
/// ```no_run
/// # use yara::{Compiler, Rules, Yara};
/// {  // Initialize the library...
///     let compiler = Compiler::new()?;
///     // ...
/// } // De-initialize the library...
///
/// {  // Initialize the again library...
///     let rules = Rules::load_from_file("compiled_rules.yr")?;
///     // ...
/// } // De-initialize the library...
///
/// let _yara = Yara::new()?;
/// // Go on, the library will be initialized until the end of the scope.
/// # Ok::<(), yara::Error>(())
/// ```
///
/// This is also true for multithreading: before version 3.8.0 of Yara, thread allocates memory on
/// the thread local storage for regexp. This memory is de-allocated when a scan, unless there is a
/// living Yara object on the current thread.
///
/// Therefore, you might want to keep a `Yara` object alive on the threads you use to scan, to
/// reduce allocation overhead.
///
/// ```no_run
/// # use yara::{Compiler, Rules, Yara};
/// let rules = Rules::load_from_file("compiled_rules.yr")?;
///
/// crossbeam::scope(|scope| {
///     scope.spawn(|_| {
///         // Allocate thread-local memory for scan...
///         rules.scan_file("file1.bin", 10);
///         // Free thread-local memory for scan...
///
///         // Allocate thread-local memory for scan...
///         rules.scan_file("file2.bin", 10);
///         // Free thread-local memory for scan...
///
///         // Memory will be freed when leaving the scope.
///         let _yara = Yara::new();
///         // Allocate thread-local memory for scan...
///         rules.scan_file("file3.bin", 10);
///         rules.scan_file("file4.bin", 10);
///     });
/// });
/// # Ok::<(), yara::Error>(())
/// ```
///
/// # Implementation notes
///
/// libyara asks to call `yr_initialize` before use the library.
/// Because yara keeps a count of how many times `yr_initialize` is used,
/// it doesn't matter if this struct is constructed multiple times.
pub struct Yara {
    _token: InitializationToken,
}

impl Yara {
    /// Create and initialize the library.
    pub fn new() -> Result<Yara, YaraError> {
        InitializationToken::new().map(|token| Yara { _token: token })
    }

    /// Set the stack size.
    pub fn set_configuration_stack_size(&self, value: u32) -> Result<(), YaraError> {
        configuration::set_stack_size(value)
    }

    /// Set the maximum number of strings to allow per yara rule.
    pub fn set_configuration_max_strings_per_rule(&self, value: u32) -> Result<(), YaraError> {
        configuration::set_max_strings_per_rule(value)
    }

    /// Set the maximum number of bytes to allow per yara match.
    pub fn set_configuration_max_match_data(&self, value: u32) -> Result<(), YaraError> {
        configuration::set_max_match_data(value)
    }

    /// Set the maximum size of chunks scanned from a process memory.
    pub fn set_configuration_max_process_memory_chunk(&self, value: u64) -> Result<(), YaraError> {
        configuration::set_max_process_memory_chunk(value)
    }

    /// Get the configured stack size.
    pub fn get_configuration_stack_size(&self) -> Result<u32, YaraError> {
        configuration::get_stack_size()
    }

    /// Get the maximum number of strings to allow per yara rule.
    pub fn get_configuration_max_strings_per_rule(&self) -> Result<u32, YaraError> {
        configuration::get_max_strings_per_rule()
    }

    /// Get the maximum number of bytes to allow per yara match.
    pub fn get_configuration_max_match_data(&self) -> Result<u32, YaraError> {
        configuration::get_max_match_data()
    }

    /// Get the maximum size of chunks scanned from a process memory.
    pub fn get_configuration_max_process_memory_chunk(&self) -> Result<u64, YaraError> {
        configuration::get_max_process_memory_chunk()
    }

    /// Create and initialize the library.
    #[deprecated = "Use new"]
    pub fn create() -> Result<Yara, YaraError> {
        Self::new()
    }

    /// Create a new compiler.
    #[deprecated = "Use Compiler::new"]
    pub fn new_compiler(&self) -> Result<Compiler, YaraError> {
        Compiler::new()
    }

    /// Load rules from a pre-compiled rules file.
    // TODO Take AsRef<Path> ?
    #[deprecated = "Use Rules::load_from_file"]
    pub fn load_rules(&self, filename: &str) -> Result<Rules, YaraError> {
        Rules::load_from_file(filename)
    }
}
