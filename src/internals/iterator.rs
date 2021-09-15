use std::ptr;
use yara_sys::{size_t, YR_MEMORY_BLOCK, YR_MEMORY_BLOCK_ITERATOR};

#[derive(Debug)]
pub struct MemoryBlock<'a> {
    /// base contains the base address of the current block
    base: u64,
    /// size contains the size of the current block
    size: size_t,
    /// data is used to read size bytes into a byte slice
    data: &'a [u8],
}

impl<'a> MemoryBlock<'a> {
    pub fn new(base: u64, size: size_t, data: &'a [u8]) -> Self {
        Self { base, size, data }
    }

    fn as_yara(&mut self) -> YR_MEMORY_BLOCK {
        let fetch_data = if self.size == 0 {
            mem_block_fetch_data_null
        } else {
            mem_block_fetch_data
        };

        YR_MEMORY_BLOCK {
            base: self.base,
            size: self.size,
            context: self as *mut MemoryBlock as *mut std::os::raw::c_void,
            fetch_data: Some(fetch_data),
        }
    }
}

pub trait MemoryBlockIterator {
    fn first(&mut self) -> Option<MemoryBlock>;
    fn next(&mut self) -> Option<MemoryBlock>;
}

pub trait MemoryBlockIteratorSized: MemoryBlockIterator {
    fn file_size(&mut self) -> u64;
}

#[derive(Debug)]
pub struct WrapperMemoryBlockIterator<T> {
    iter: T,
    mem_block: std::mem::MaybeUninit<YR_MEMORY_BLOCK>,
}

impl<T> WrapperMemoryBlockIterator<T> {
    pub fn new(iter: T) -> Self {
        Self {
            iter,
            mem_block: std::mem::MaybeUninit::uninit(),
        }
    }
}

impl<T: MemoryBlockIterator> WrapperMemoryBlockIterator<T> {
    pub fn as_yara(&mut self) -> YR_MEMORY_BLOCK_ITERATOR {
        YR_MEMORY_BLOCK_ITERATOR {
            context: self as *mut WrapperMemoryBlockIterator<T> as *mut std::os::raw::c_void,
            first: Some(mem_block_iterator_first::<T>),
            next: Some(mem_block_iterator_next::<T>),
            file_size: None,
            last_error: 0,
        }
    }
}

impl<T: MemoryBlockIteratorSized> WrapperMemoryBlockIterator<T> {
    pub fn as_yara_sized(&mut self) -> YR_MEMORY_BLOCK_ITERATOR {
        YR_MEMORY_BLOCK_ITERATOR {
            context: self as *mut WrapperMemoryBlockIterator<T> as *mut std::os::raw::c_void,
            first: Some(mem_block_iterator_first::<T>),
            next: Some(mem_block_iterator_next::<T>),
            file_size: Some(mem_block_iterator_file_size::<T>),
            last_error: 0,
        }
    }
}

unsafe extern "C" fn mem_block_iterator_first<T: MemoryBlockIterator>(
    iter: *mut YR_MEMORY_BLOCK_ITERATOR,
) -> *mut YR_MEMORY_BLOCK {
    let context = &mut *((*iter).context as *mut WrapperMemoryBlockIterator<T>);
    let mut mem_block = context.iter.first();
    match mem_block.as_mut() {
        Some(mem_block) => {
            context.mem_block.write(mem_block.as_yara());
            context.mem_block.as_mut_ptr()
        }
        None => ptr::null_mut(),
    }
}

unsafe extern "C" fn mem_block_iterator_next<T: MemoryBlockIterator>(
    iter: *mut YR_MEMORY_BLOCK_ITERATOR,
) -> *mut YR_MEMORY_BLOCK {
    let context = &mut *((*iter).context as *mut WrapperMemoryBlockIterator<T>);
    let _ = context.mem_block.assume_init();
    let mut mem_block = context.iter.next();
    match mem_block.as_mut() {
        Some(mem_block) => {
            context.mem_block.write(mem_block.as_yara());
            context.mem_block.as_mut_ptr()
        }
        None => ptr::null_mut(),
    }
}

unsafe extern "C" fn mem_block_iterator_file_size<T: MemoryBlockIteratorSized>(
    iter: *mut YR_MEMORY_BLOCK_ITERATOR,
) -> u64 {
    let context = &mut *((*iter).context as *mut WrapperMemoryBlockIterator<T>);
    context.iter.file_size()
}

unsafe extern "C" fn mem_block_fetch_data_null(_: *mut YR_MEMORY_BLOCK) -> *const u8 {
    ptr::null()
}

unsafe extern "C" fn mem_block_fetch_data(mem_block: *mut YR_MEMORY_BLOCK) -> *const u8 {
    let mem_block = &mut *((*mem_block).context as *mut MemoryBlock);
    mem_block.data.as_ptr()
}
