use std::io::{Read, Result, Write};

use yara_sys::YR_STREAM;

pub struct ReadStream<'r> {
    reader: &'r mut dyn Read,
    result: Result<()>,
}

impl<'r> ReadStream<'r> {
    pub fn new(reader: &'r mut dyn Read) -> Self {
        Self {
            reader,
            result: Ok(()),
        }
    }

    pub fn as_yara(&mut self) -> YR_STREAM {
        YR_STREAM {
            user_data: self as *mut ReadStream as *mut std::os::raw::c_void,
            read: Some(stream_read_func),
            write: None,
        }
    }

    pub fn result(self) -> Result<()> {
        self.result
    }
}

pub struct WriteStream<'w> {
    writer: &'w mut dyn Write,
    result: Result<()>,
}

impl<'w> WriteStream<'w> {
    pub fn new(writer: &'w mut dyn Write) -> Self {
        Self {
            writer,
            result: Ok(()),
        }
    }

    pub fn as_yara(&mut self) -> YR_STREAM {
        YR_STREAM {
            user_data: self as *mut Self as *mut std::os::raw::c_void,
            read: None,
            write: Some(stream_write_func),
        }
    }

    pub fn result(self) -> Result<()> {
        self.result
    }
}

unsafe extern "C" fn stream_read_func(
    ptr: *mut ::std::os::raw::c_void,
    size: u64,
    count: u64,
    user_data: *mut ::std::os::raw::c_void,
) -> u64 {
    let this: &mut ReadStream = &mut *(user_data as *mut ReadStream);
    if this.result.is_err() {
        return 0;
    }

    let buffer = std::slice::from_raw_parts_mut(ptr as *mut u8, (size * count) as usize);
    let result = this.reader.read(buffer);

    match result {
        // FIXME: what if read_size is not a multiple of size ?
        Ok(read_size) => read_size as u64 / size,
        Err(e) => {
            this.result = Err(e);
            0
        }
    }
}

unsafe extern "C" fn stream_write_func(
    ptr: *const ::std::os::raw::c_void,
    size: u64,
    count: u64,
    user_data: *mut ::std::os::raw::c_void,
) -> u64 {
    let this: &mut WriteStream = &mut *(user_data as *mut WriteStream);
    if this.result.is_err() {
        return 0;
    }

    let buffer = std::slice::from_raw_parts(ptr as *const u8, (size * count) as usize);
    let result = this.writer.write_all(buffer);

    match result {
        Ok(()) => count,
        Err(e) => {
            this.result = Err(e);
            0
        }
    }
}
