use crate::{OwnedSid, Sid};
use windows_sys::Win32::Security::PSID;

/// A type that can clone a SID from a raw Windows pointer into independent storage.
///
/// This trait is intentionally open so applications can use their own SID storage
/// types with Windows APIs exposed by this crate.
///
/// # Safety
/// Implementations must copy the SID data into storage owned by the returned
/// value. The returned value must not borrow from, retain pointers into, or
/// otherwise depend on the `PSID` passed to [`CloneSidFromRaw::clone_sid_from_raw`].
pub unsafe trait CloneSidFromRaw: Sized {
    /// Clones a SID from a raw Windows `PSID`.
    ///
    /// # Safety
    /// `raw` must be non-null and point to a valid SID for the duration of this
    /// call.
    #[must_use]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self;
}

// SAFETY: OwnedSid guarantees that conversion from &Sid creates independent
// owned storage and does not retain pointers into the source SID.
unsafe impl<T: OwnedSid> CloneSidFromRaw for T {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees that `raw` points to a valid SID for
        // the duration of this call.
        let sid = unsafe { Sid::from_raw(raw) };
        sid.into()
    }
}

#[cfg(test)]
mod tests {
    use super::CloneSidFromRaw;
    use crate::{SecurityIdentifier, Sid, StackSid, well_known};
    use std::boxed::Box;

    fn clone_sid_from_raw_copies_as<T>(source: &Sid)
    where
        T: CloneSidFromRaw + AsRef<Sid>,
    {
        // SAFETY: `source.as_raw()` remains valid for the duration of the call.
        let cloned = unsafe { T::clone_sid_from_raw(source.as_raw()) };

        assert_eq!(cloned.as_ref(), source);
        assert!(!core::ptr::addr_eq(cloned.as_ref(), source));
    }

    #[test]
    fn owned_sid_types_clone_into_independent_storage() {
        let source = well_known::BUILTIN_ADMINISTRATORS.as_sid();

        clone_sid_from_raw_copies_as::<StackSid>(source);
        clone_sid_from_raw_copies_as::<SecurityIdentifier>(source);
        clone_sid_from_raw_copies_as::<Box<Sid>>(source);
    }
}
