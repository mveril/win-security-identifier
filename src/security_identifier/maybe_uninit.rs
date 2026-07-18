#[cfg(not(has_ptr_metadata))]
use crate::polyfills_ptr::from_raw_parts_mut;
use crate::{SecurityIdentifier, Sid, SidSizeInfo};
#[cfg(all(feature = "alloc", not(feature = "std")))]
use ::alloc::{alloc, boxed::Box};
#[cfg(has_ptr_metadata)]
use core::ptr::from_raw_parts_mut;
use core::{
    alloc::Layout,
    mem,
    ptr::{self, NonNull},
};
#[cfg(feature = "std")]
use std::alloc;

/// Internal helper that owns uninitialized memory for a `Sid`.
///
/// The memory is allocated with the correct layout and metadata for
/// a `Sid` DST, but the value is not considered initialized until
/// `assume_init` is called.
pub(super) struct MaybeUninitSecurityIdentifier {
    base: NonNull<u8>,
    layout: Layout,
    sub_authority_count: u8,
}

impl MaybeUninitSecurityIdentifier {
    /// Allocate uninitialized storage for a `Sid` with the given size info.
    pub fn alloc(size_info: &SidSizeInfo) -> Self {
        let layout = size_info.layout();

        // SAFETY: `layout` is a valid non-zero-sized layout for a `Sid` value.
        let mem_ptr = unsafe { alloc::alloc(layout) };
        let base = NonNull::new(mem_ptr).unwrap_or_else(|| alloc::handle_alloc_error(layout));
        let sub_authority_count = size_info.sub_authority_count();

        Self {
            base,
            layout,
            sub_authority_count,
        }
    }

    const fn sid_ptr(&self) -> *mut Sid {
        let meta = self.sub_authority_count as usize;
        let base_opaque = self.base.as_ptr().cast::<()>();
        from_raw_parts_mut(base_opaque, meta)
    }

    /// Returns a mutable raw pointer to the underlying uninitialized `Sid`.
    ///
    /// # Safety
    /// - The caller must only *write* to the pointed-to value until
    ///   `assume_init` is called.
    /// - The caller must ensure that all fields of `Sid` are fully and
    ///   correctly initialized before calling `assume_init`.
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "Because we return a mut pointer in public we should use a &mut self"
    )]
    pub const fn as_mut_ptr(&mut self) -> *mut Sid {
        self.sid_ptr()
    }

    /// Turn this uninitialized handle into a fully initialized `SecurityIdentifier`.
    ///
    /// After this call, the memory is owned by a `Box<Sid>` and this helper
    /// must not be used again.
    ///
    /// # Safety
    /// - The caller must guarantee that the `Sid` pointed to by this handle
    ///   has been fully initialized and is a valid `Sid` value.
    pub unsafe fn assume_init(self) -> SecurityIdentifier {
        // Build the fat pointer before preventing `Drop`.
        let raw_ptr = self.sid_ptr();
        #[expect(clippy::mem_forget, reason = "We will box the raw pointer just after")]
        mem::forget(self);

        // SAFETY:
        // - `raw_ptr` comes from `alloc::alloc` with layout `this.layout`.
        // - Ownership is transferred to `Box`, `Drop` will not deallocate.
        let inner = unsafe { Box::from_raw(raw_ptr) };

        SecurityIdentifier { inner }
    }
}

/// Resizes an initialized boxed SID and appends initialized tail values.
///
/// # Safety
/// `new_size_info` must describe the current count plus `appended.len()`.
pub(super) unsafe fn grow_box(value: &mut Box<Sid>, new_size_info: &SidSizeInfo, appended: &[u32]) {
    let old_layout = Layout::for_value(value.as_ref());
    let new_layout = new_size_info.layout();

    let old_base = ptr::from_mut::<Sid>(value.as_mut()).cast::<u8>();
    // SAFETY:
    // - `old_base` was allocated for `old_layout` by the global allocator;
    // - `new_layout` has the same alignment because only the DST tail length changes;
    // - `value` is not accessed again unless realloc fails, in which case the
    //   original allocation and Box remain valid.
    let resized = unsafe { alloc::realloc(old_base, old_layout, new_layout.size()) };
    let resized = NonNull::new(resized).unwrap_or_else(|| alloc::handle_alloc_error(new_layout));

    if !appended.is_empty() {
        // SAFETY: the allocation was grown to `new_layout`; `old_layout.size()`
        // points at the first new tail element and `appended` exactly fills the growth.
        let appended_base = unsafe { resized.as_ptr().add(old_layout.size()) };
        #[expect(
            clippy::cast_ptr_alignment,
            reason = "SID layouts and their tail offsets are aligned for u32"
        )]
        let appended_ptr = appended_base.cast::<u32>();
        // SAFETY: the destination has room for every appended value and does not overlap.
        unsafe { appended_ptr.copy_from_nonoverlapping(appended.as_ptr(), appended.len()) };
    }

    let sid_ptr: *mut Sid = from_raw_parts_mut(
        resized.as_ptr().cast::<()>(),
        new_size_info.sub_authority_count() as usize,
    );
    // SAFETY: all tail elements described by the new metadata are initialized.
    // Updating the count restores the SID header/DST metadata invariant before
    // ownership is reconstructed.
    unsafe { (*sid_ptr).sub_authority_count = new_size_info.sub_authority_count() };
    // SAFETY: `sid_ptr` describes the complete resized allocation exactly once.
    let replacement = unsafe { Box::from_raw(sid_ptr) };
    // SAFETY: successful realloc invalidated the old Box allocation, so replace
    // the Box bits without attempting to drop the stale pointer.
    unsafe { ptr::write(&raw mut *value, replacement) };
}

/// Shrinks an initialized boxed SID to an initialized prefix.
///
/// # Safety
/// `new_size_info` must describe a non-zero count smaller than `value`'s count.
pub(super) unsafe fn shrink_box(value: &mut Box<Sid>, new_size_info: &SidSizeInfo) {
    let old_layout = Layout::for_value(value.as_ref());
    let new_layout = new_size_info.layout();

    let old_base = ptr::from_mut::<Sid>(value.as_mut()).cast::<u8>();
    // SAFETY: same allocation and alignment reasoning as `grow_box`; the
    // retained prefix is fully initialized and fits in `new_layout`.
    let resized = unsafe { alloc::realloc(old_base, old_layout, new_layout.size()) };
    let resized = NonNull::new(resized).unwrap_or_else(|| alloc::handle_alloc_error(new_layout));
    let sid_ptr: *mut Sid = from_raw_parts_mut(
        resized.as_ptr().cast::<()>(),
        new_size_info.sub_authority_count() as usize,
    );
    // SAFETY: the retained tail prefix is initialized and the new allocation
    // exactly matches the reconstructed Box metadata.
    unsafe { (*sid_ptr).sub_authority_count = new_size_info.sub_authority_count() };
    // SAFETY: `sid_ptr` describes the complete resized allocation exactly once.
    let replacement = unsafe { Box::from_raw(sid_ptr) };
    // SAFETY: successful realloc invalidated the old Box allocation.
    unsafe { ptr::write(&raw mut *value, replacement) };
}

impl Drop for MaybeUninitSecurityIdentifier {
    fn drop(&mut self) {
        // SAFETY:
        // - `self.base` was allocated by `alloc::alloc` with `self.layout`.
        // - `assume_init` would wrap `self` in `ManuallyDrop`, so this Drop
        //   only runs for still-owned allocations.
        unsafe {
            alloc::dealloc(self.base.as_ptr(), self.layout);
        }
    }
}

impl From<Box<Sid>> for MaybeUninitSecurityIdentifier {
    fn from(value: Box<Sid>) -> Self {
        let layout = Layout::for_value(value.as_ref());
        let sub_authority_count = value.sub_authority_count;
        let base = Box::into_raw(value).cast::<u8>();
        // Safety: We know the PTR from the box is not null
        let base = unsafe { NonNull::new_unchecked(base) };
        Self {
            base,
            layout,
            sub_authority_count,
        }
    }
}
