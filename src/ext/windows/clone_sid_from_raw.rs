use crate::{SecurityIdentifier, StackSid, sid::Sid};
use windows_sys::Win32::Security::PSID;

/// A type that can safely clone a SID from a raw Windows pointer.
///
/// # Safety
/// Implementations must clone the SID data and must not return a value that
/// borrows from, stores, or otherwise depends on the raw `PSID` passed to
/// [`CloneSidFromRaw::clone_sid_from_raw`]. Callers may pass pointers into
/// temporary buffers that become invalid immediately after the call returns.
///
/// Owning/cloning SID types satisfy this contract. Lifetime-carrying pointer
/// wrappers may also implement this trait when their implementation ensures the
/// returned pointer refers to storage that outlives the returned value.
///
/// Raw pointers do not implement this trait, because returning the temporary
/// token SID pointer directly would create a dangling pointer.
///
/// # Examples
///
/// ```
/// # #[cfg(windows)]
/// # {
/// use win_security_identifier::{CloneSidFromRaw, SecurityIdentifier, well_known};
///
/// let sid = well_known::BUILTIN_ADMINISTRATORS.as_sid();
/// let cloned = unsafe { SecurityIdentifier::clone_sid_from_raw(sid.as_raw()) };
///
/// assert_eq!(cloned.as_sid(), sid);
/// # }
/// ```
pub unsafe trait CloneSidFromRaw: Sized {
    /// Clones a SID from a raw Windows `PSID`.
    ///
    /// # Safety
    /// `sid` must be non-null and point to a valid SID for the duration of this
    /// call.
    #[must_use]
    unsafe fn clone_sid_from_raw(sid: PSID) -> Self;
}

// SAFETY: SecurityIdentifier copies the SID bytes into owned heap storage.
unsafe impl CloneSidFromRaw for SecurityIdentifier {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        let sid = unsafe { Sid::from_raw(raw) };
        sid.into()
    }
}

// SAFETY: StackSid copies the SID bytes into owned stack storage.
unsafe impl CloneSidFromRaw for StackSid {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        let sid = unsafe { Sid::from_raw(raw) };
        sid.into()
    }
}

// SAFETY: Box<Sid> copies the SID bytes into owned heap storage.
unsafe impl CloneSidFromRaw for Box<Sid> {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        let sid = unsafe { Sid::from_raw(raw) };
        sid.into()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "Expect is not an issue in tests")]
mod tests {
    use super::*;
    use crate::SidIdentifierAuthority;
    use core::ptr;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn clone_sid_from_raw_clones_sid(sid in arb_stack_sid()) {
            clone_sid_from_raw_clones_sid_as::<SecurityIdentifier>(&sid);
            clone_sid_from_raw_clones_sid_as::<StackSid>(&sid);
            clone_sid_from_raw_clones_sid_as::<Box<Sid>>(&sid);
        }
    }

    fn clone_sid_from_raw_clones_sid_as<T>(source: &StackSid)
    where
        T: CloneSidFromRaw + AsRef<Sid>,
    {
        let source = source.as_sid();

        // SAFETY: `source.as_raw()` points to `source`, which remains alive for
        // the duration of this call.
        let current = unsafe { T::clone_sid_from_raw(source.as_raw()) };

        assert_eq!(
            current.as_ref(),
            source,
            "cloned SID must preserve the source value"
        );
        assert!(
            !ptr::addr_eq(current.as_ref(), source),
            "cloned SID must not borrow the source buffer"
        );
    }

    fn arb_stack_sid() -> impl Strategy<Value = StackSid> {
        (
            any::<[u8; 6]>(),
            proptest::collection::vec(any::<u32>(), 1..=15),
        )
            .prop_map(|(identifier_authority, sub_authorities)| {
                StackSid::try_new(
                    SidIdentifierAuthority::new(identifier_authority),
                    &sub_authorities,
                )
                .expect("generated SID parts must be valid")
            })
    }
}
