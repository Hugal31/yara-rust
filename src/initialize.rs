use std::collections::HashMap;
use std::sync::Mutex;
use std::thread;

use lazy_static::lazy_static;

use crate::{errors::*, internals};

lazy_static! {
   /// Keep a reference on how many "InitializeToken" we have per thread, to run yr_finalize_thread
   /// when needed.
   /// TODO: Assess performances, find if it is possible to do better.
   static ref THREAD_COUNTERS: Mutex<HashMap<thread::ThreadId, usize>> = Mutex::new(HashMap::new());
}

/// Token to initialize the library.
///
/// # Implementation notes
///
/// libyara asks to call `yr_initialize` before use the library.
/// Because yara keeps a count of how many times `yr_initialize` is used,
/// it doesn't matter if this struct is constructed multiple times.
///
/// However, since we already keep a count on how many `InitializationToken` instances there are on
/// a thread, we only call yr_initialize and yr_finalize once per thread.
///
/// To call yr_finalize_thread (required until Yara 3.8.0), we store a number of
/// `InitializationToken` living in each thread. When this number reaches 0, we call
/// yr_finalize_thread.
#[derive(Debug)]
pub struct InitializationToken;

impl InitializationToken {
    /// Create and initialize the library.
    pub fn new() -> Result<InitializationToken, YaraError> {
        // Increment the thread counter.
        let mut thread_counters = THREAD_COUNTERS
            .lock()
            .expect("mutex should not be poisoned");
        let counter = thread_counters.entry(thread::current().id()).or_insert(0);
        *counter += 1;

        if *counter == 1 {
            internals::initialize()?;
        }

        Ok(InitializationToken)
    }
}

/// Finalize the Yara library
impl Drop for InitializationToken {
    fn drop(&mut self) {
        // Decrement the thread counter, and call yr_finalize_thread if it reaches 0.
        let thread_id = thread::current().id();
        let mut thread_counters = THREAD_COUNTERS
            .lock()
            .expect("mutex should not be poisoned");
        let n_threads = thread_counters
            .get_mut(&thread_id)
            .expect("incorrect use of THREAD_COUNTERS");

        if *n_threads > 1 {
            *n_threads -= 1;
        } else {
            thread_counters.remove(&thread_id);
            internals::finalize_thread();
            internals::finalize().expect("Expect correct Yara finalization");
        }
    }
}
