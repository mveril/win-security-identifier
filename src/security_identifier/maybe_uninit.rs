#[cfg(not(has_ptr_metadata))]
use crate::polyfills_ptr::from_raw_parts_mut;
use crate::{SecurityIdentifier, Sid, SidSizeInfo};
#[cfg(has_ptr_metadata)]
use core::ptr::from_raw_parts_mut;
use core::{alloc::Layout, mem, ptr::NonNull};

#[cfg(all(feature = "alloc", not(feature = "std")))]
use ::alloc::alloc;
#[cfg(feature = "std")]
use std::alloc;

/// Owns uninitialized storage for a SID allocation.
pub(super) struct MaybeUninitSecurityIdentifier {
    base: NonNull<u8>,
    layout: Layout,
    sub_authority_count: u8,
}

impl MaybeUninitSecurityIdentifier {
    pub fn alloc(size_info: &SidSizeInfo) -> Self {
        let layout = size_info.layout();
        // SAFETY: `layout` is non-zero and was produced for a valid SID size.
        let memory = unsafe { alloc::alloc(layout) };
        let base = NonNull::new(memory).unwrap_or_else(|| alloc::handle_alloc_error(layout));
        Self {
            base,
            layout,
            sub_authority_count: size_info.sub_authority_count(),
        }
    }

    const fn sid_ptr(&self) -> *mut Sid {
        from_raw_parts_mut(
            self.base.as_ptr().cast::<()>(),
            self.sub_authority_count as usize,
        )
    }

    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "mutable access communicates that the allocation is being initialized"
    )]
    pub const fn as_mut_ptr(&mut self) -> *mut Sid {
        self.sid_ptr()
    }

    /// # Safety
    /// The SID prefix and all `sub_authority_count` tail values must be initialized.
    pub unsafe fn assume_init(self) -> SecurityIdentifier {
        let this = mem::ManuallyDrop::new(self);
        let inner = this.base;
        let capacity = this.sub_authority_count;
        SecurityIdentifier { inner, capacity }
    }
}

impl Drop for MaybeUninitSecurityIdentifier {
    fn drop(&mut self) {
        // SAFETY: this allocation was created with the same allocator and layout.
        unsafe { alloc::dealloc(self.base.as_ptr(), self.layout) };
    }
}
