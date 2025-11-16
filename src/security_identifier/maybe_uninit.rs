#[cfg(not(has_ptr_metadata))]
use crate::polyfills_ptr::from_raw_parts_mut;
use crate::{SecurityIdentifier, Sid, SidSizeInfo};
#[cfg(all(feature = "alloc", not(feature = "std")))]
use ::alloc::{alloc, boxed::Box};
#[cfg(has_ptr_metadata)]
use core::ptr::from_raw_parts_mut;
use core::{alloc::Layout, mem::ManuallyDrop, ptr::NonNull};
#[cfg(feature = "std")]
use std::alloc;

/// Internal helper that owns uninitialized memory for a `Sid`.
///
/// The memory is allocated with the correct layout and metadata for
/// a `Sid` DST, but the value is not considered initialized until
/// `assume_init` is called.
pub(super) struct MaybeUninitSecurityIdentifier {
    ptr: NonNull<Sid>,
    layout: Layout,
}

impl MaybeUninitSecurityIdentifier {
    /// Allocate uninitialized storage for a `Sid` with the given size info.
    ///
    /// This does not initialize any field of `Sid`; it only reserves
    /// correctly sized and aligned memory and builds a fat pointer.
    pub fn alloc(size_info: SidSizeInfo) -> Self {
        let layout = size_info.get_layout();

        // SAFETY: `layout` is a valid non-zero-sized layout, produced by
        // `SidSizeInfo::get_layout` for a `Sid` value.
        let mem_ptr = unsafe { alloc::alloc(layout) };
        if mem_ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }

        let sub_authority_count = size_info.get_sub_authority_count();
        let base_ptr = mem_ptr.cast::<()>();

        // SAFETY:
        // - `base_ptr` comes from a valid allocation with `layout`.
        // - `sub_authority_count` is the correct slice length metadata
        //   for the trailing `[u32]` part of `Sid`.
        let sid_ptr: *mut Sid =
            unsafe { from_raw_parts_mut(base_ptr, sub_authority_count as usize) };

        // SAFETY: `sid_ptr` is non-null because `alloc::alloc` either returns
        // null (handled above) or a valid non-null pointer.
        let ptr = unsafe { NonNull::new_unchecked(sid_ptr) };

        Self { ptr, layout }
    }

    /// Returns a mutable raw pointer to the underlying uninitialized `Sid`.
    ///
    /// # Safety
    /// - The caller must only *write* to the pointed-to value until
    ///   `assume_init` is called.
    /// - The caller must ensure that all fields of `Sid` are fully and
    ///   correctly initialized before calling `assume_init`.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut Sid {
        self.ptr
    }

    /// Turn this uninitialized handle into a fully initialized `SecurityIdentifier`.
    ///
    /// After this call, the memory is owned and managed by a `Box<Sid>`
    /// inside `SecurityIdentifier`, and this helper must not be used again.
    ///
    /// # Safety
    /// - The caller must guarantee that the `Sid` pointed to by `self.ptr`
    ///   has been fully initialized and is a valid `Sid` value.
    pub unsafe fn assume_init(self) -> SecurityIdentifier {
        let mut this = ManuallyDrop::new(self);
        let raw_ptr = this.ptr.as_ptr();

        // SAFETY:
        // - `raw_ptr` comes from `alloc::alloc` with the same layout stored
        //   in `self.layout`.
        // - Ownership of the allocation is transferred to `Box`, and this
        //   helper will not deallocate it in `Drop` because `self` is wrapped
        //   in `ManuallyDrop`.
        let inner = unsafe { Box::from_raw(raw_ptr) };

        SecurityIdentifier { inner }
    }
}

impl Drop for MaybeUninitSecurityIdentifier {
    fn drop(&mut self) {
        let raw = self.ptr.as_ptr().cast::<u8>();

        // SAFETY:
        // - `raw` was allocated by `alloc::alloc` with `self.layout` in `alloc`.
        // - `assume_init` has not been called, otherwise `self` would have
        //   been wrapped in `ManuallyDrop` and this `Drop` would not run.
        // - Therefore it is correct to deallocate `raw` with `self.layout`.
        unsafe {
            alloc::dealloc(raw, self.layout);
        }
    }
}
