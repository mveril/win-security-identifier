use crate::sid::Sid;
use std::os::raw::c_void;

pub(super) unsafe fn from_raw_parts_mut(src: *mut c_void, dynamic_size_count: usize) -> *mut Sid {
    core::ptr::slice_from_raw_parts_mut(src, dynamic_size_count) as *mut Sid
}

pub(super) const unsafe fn from_raw_parts(src: *mut c_void, dynamic_size_count: usize) -> *mut Sid {
    core::ptr::slice_from_raw_parts(src, dynamic_size_count) as *mut Sid
}

#[allow(dead_code)]
pub(super) const fn metadata(sid: *const Sid) -> usize {
    unsafe {
        let slice = &*(sid as *const [()]);
        slice.len()
    }
}
