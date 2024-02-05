use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
    ptr,
};
use yara_sys::{YR_MEMORY_BLOCK, YR_MEMORY_BLOCK_ITERATOR};

#[derive(Debug)]
pub struct MemoryBlock<'a> {
    base: u64,
    data: &'a [u8],
}

impl<'a> MemoryBlock<'a> {
    pub fn new(base: u64, data: &'a [u8]) -> Self {
        Self { base, data }
    }

    fn into_yara(self) -> YR_MEMORY_BLOCK {
        YR_MEMORY_BLOCK {
            base: self.base,
            size: self.data.len() as _,
            context: if self.data.is_empty() {
                std::ptr::null_mut()
            } else {
                self.data.as_ptr() as *const _ as *mut _
            },
            fetch_data: Some(mem_block_fetch_data),
        }
    }
}

pub trait MemoryBlockIterator {
    fn first(&mut self) -> Option<MemoryBlock>;
    fn next(&mut self) -> Option<MemoryBlock>;
}

impl<T> MemoryBlockIterator for Box<T>
where
    T: MemoryBlockIterator,
{
    fn first(&mut self) -> Option<MemoryBlock> {
        (**self).first()
    }

    fn next(&mut self) -> Option<MemoryBlock> {
        (**self).next()
    }
}

pub trait MemoryBlockIteratorSized: MemoryBlockIterator {
    fn file_size(&mut self) -> u64;
}

impl<T> MemoryBlockIteratorSized for Box<T>
where
    T: MemoryBlockIteratorSized,
{
    fn file_size(&mut self) -> u64 {
        (**self).file_size()
    }
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
    // Clippy warns there is a needless lifetime on this.
    // I don't know if I missed something or if clippy is wrong, but removing the lifetime is
    // unsafe.
    #[allow(clippy::needless_lifetimes)]
    pub fn as_yara<'a>(&'a mut self) -> impl DerefMut<Target = YR_MEMORY_BLOCK_ITERATOR> + 'a {
        SafeYrMemoryBlockIterator::new(YR_MEMORY_BLOCK_ITERATOR {
            context: self as *mut WrapperMemoryBlockIterator<T> as *mut std::os::raw::c_void,
            first: Some(mem_block_iterator_first::<T>),
            next: Some(mem_block_iterator_next::<T>),
            file_size: None,
            last_error: 0,
        })
    }
}

impl<T: MemoryBlockIteratorSized> WrapperMemoryBlockIterator<T> {
    #[allow(clippy::needless_lifetimes)]
    pub fn as_yara_sized<'a>(
        &'a mut self,
    ) -> impl DerefMut<Target = YR_MEMORY_BLOCK_ITERATOR> + 'a {
        SafeYrMemoryBlockIterator::new(YR_MEMORY_BLOCK_ITERATOR {
            context: self as *mut WrapperMemoryBlockIterator<T> as *mut std::os::raw::c_void,
            first: Some(mem_block_iterator_first::<T>),
            next: Some(mem_block_iterator_next::<T>),
            file_size: Some(mem_block_iterator_file_size::<T>),
            last_error: 0,
        })
    }
}

struct SafeYrMemoryBlockIterator<'a> {
    iterator: YR_MEMORY_BLOCK_ITERATOR,
    _marker: PhantomData<&'a ()>,
}

impl<'a> SafeYrMemoryBlockIterator<'a> {
    pub fn new(iterator: YR_MEMORY_BLOCK_ITERATOR) -> Self {
        Self {
            iterator,
            _marker: PhantomData,
        }
    }
}

impl<'a> Deref for SafeYrMemoryBlockIterator<'a> {
    type Target = YR_MEMORY_BLOCK_ITERATOR;

    fn deref(&self) -> &Self::Target {
        &self.iterator
    }
}

impl<'a> DerefMut for SafeYrMemoryBlockIterator<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.iterator
    }
}

unsafe extern "C" fn mem_block_iterator_first<T: MemoryBlockIterator>(
    iter: *mut YR_MEMORY_BLOCK_ITERATOR,
) -> *mut YR_MEMORY_BLOCK {
    let context = &mut *((*iter).context as *mut WrapperMemoryBlockIterator<T>);
    let mem_block = context.iter.first();
    match mem_block {
        Some(mem_block) => {
            context.mem_block.write(mem_block.into_yara());
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
    let mem_block = context.iter.next();
    match mem_block {
        Some(mem_block) => {
            context.mem_block.write(mem_block.into_yara());
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

unsafe extern "C" fn mem_block_fetch_data(mem_block: *mut YR_MEMORY_BLOCK) -> *const u8 {
    (*mem_block).context as *const u8
}
