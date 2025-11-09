use crate::sid::Sid;

#[allow(dead_code)]
#[allow(clippy::cast_ptr_alignment)]
pub const fn from_raw_parts_mut(src: *mut (), dynamic_size_count: usize) -> *mut Sid {
    core::ptr::slice_from_raw_parts_mut(src, dynamic_size_count) as *mut Sid
}

#[allow(clippy::cast_ptr_alignment)]
pub const fn from_raw_parts(src: *const (), dynamic_size_count: usize) -> *const Sid {
    core::ptr::slice_from_raw_parts(src, dynamic_size_count) as *const Sid
}

#[allow(dead_code)]
pub const fn metadata(sid: *const Sid) -> usize {
    // SAFETY: as Sid is a fat pointer it's safe to use
    unsafe {
        let slice = &*(sid as *const [()]);
        slice.len()
    }
}
