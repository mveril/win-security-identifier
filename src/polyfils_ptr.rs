use crate::sid::Sid;
use std::{os::raw::c_void, slice};

pub(super) unsafe fn from_raw_parts_mut(src: *mut c_void, dynamic_size_count: usize) -> *mut Sid {
    unsafe { slice::from_raw_parts_mut(src, dynamic_size_count) as *mut [_] as *mut Sid }
}

pub(super) const unsafe fn from_raw_parts(src: *mut c_void, dynamic_size_count: usize) -> *mut Sid {
    unsafe { slice::from_raw_parts(src, dynamic_size_count) as *const [_] as *mut Sid }
}

pub(super) const fn metadata(sid: *const Sid) -> usize {
    unsafe {
        let slice = &*(sid as *const [()]);
        slice.len()
    }
}
