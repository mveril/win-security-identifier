use crate::{InvalidSidParts, Sid, SidIdentifierAuthority, StackSid};

#[cfg(feature = "alloc")]
use crate::SecurityIdentifier;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::boxed::Box;
#[cfg(all(feature = "alloc", feature = "std"))]
use std::boxed::Box;
#[cfg(all(windows, feature = "std"))]
use windows_sys::Win32::Security::PSID;

/// A type that owns SID storage and can construct an independent SID value.
///
/// # Safety
/// Implementations must return values that own their SID bytes independently of
/// the constructor inputs. Returned values must not borrow from, store, or
/// otherwise depend on the lifetime of `sub_authorities` or a source [`Sid`].
/// They must not retain pointers into constructor inputs, and the SID returned
/// by [`AsRef`] must remain valid for the lifetime of the owned value.
pub unsafe trait OwnedSid: AsRef<Sid> + Sized + for<'a> From<&'a Sid> {
    /// Creates a new owned SID from validated parts.
    ///
    /// # Errors
    /// Returns [`InvalidSidParts`] if the number of sub-authorities is outside
    /// the valid Windows SID range.
    fn try_new<I, S>(identifier_authority: I, sub_authorities: S) -> Result<Self, InvalidSidParts>
    where
        I: Into<SidIdentifierAuthority>,
        S: AsRef<[u32]>;

    /// Creates a new owned SID from parts without validating the sub-authority count.
    ///
    /// # Safety
    /// `sub_authorities` must contain a valid Windows SID sub-authority count.
    #[must_use]
    unsafe fn new_unchecked<I, S>(identifier_authority: I, sub_authorities: S) -> Self
    where
        I: Into<SidIdentifierAuthority>,
        S: AsRef<[u32]>;

    /// Clones a SID from a raw Windows `PSID`.
    ///
    /// # Safety
    /// `sid` must be non-null and point to a valid SID for the duration of this
    /// call.
    #[cfg(all(windows, feature = "std"))]
    #[must_use]
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        let sid = unsafe { Sid::from_raw(raw) };
        sid.into()
    }
}

// SAFETY: StackSid copies the supplied parts into its own stack storage.
unsafe impl OwnedSid for StackSid {
    #[inline]
    fn try_new<I, S>(identifier_authority: I, sub_authorities: S) -> Result<Self, InvalidSidParts>
    where
        I: Into<SidIdentifierAuthority>,
        S: AsRef<[u32]>,
    {
        Self::try_new(identifier_authority.into(), sub_authorities.as_ref())
    }

    #[inline]
    unsafe fn new_unchecked<I, S>(identifier_authority: I, sub_authorities: S) -> Self
    where
        I: Into<SidIdentifierAuthority>,
        S: AsRef<[u32]>,
    {
        // SAFETY: Forwarding the caller's unchecked constructor precondition.
        unsafe { Self::new_unchecked(identifier_authority.into(), sub_authorities.as_ref()) }
    }
}

// SAFETY: SecurityIdentifier copies the supplied parts into owned heap storage.
#[cfg(feature = "alloc")]
unsafe impl OwnedSid for SecurityIdentifier {
    #[inline]
    fn try_new<I, S>(identifier_authority: I, sub_authorities: S) -> Result<Self, InvalidSidParts>
    where
        I: Into<SidIdentifierAuthority>,
        S: AsRef<[u32]>,
    {
        Self::try_new(identifier_authority, sub_authorities)
    }

    #[inline]
    unsafe fn new_unchecked<I, S>(identifier_authority: I, sub_authorities: S) -> Self
    where
        I: Into<SidIdentifierAuthority>,
        S: AsRef<[u32]>,
    {
        // SAFETY: Forwarding the caller's unchecked constructor precondition.
        unsafe { Self::new_unchecked(identifier_authority, sub_authorities) }
    }
}

// SAFETY: Box<Sid> is produced from SecurityIdentifier, which owns heap storage.
#[cfg(feature = "alloc")]
unsafe impl OwnedSid for Box<Sid> {
    #[inline]
    fn try_new<I, S>(identifier_authority: I, sub_authorities: S) -> Result<Self, InvalidSidParts>
    where
        I: Into<SidIdentifierAuthority>,
        S: AsRef<[u32]>,
    {
        SecurityIdentifier::try_new(identifier_authority, sub_authorities).map(Into::into)
    }

    #[inline]
    unsafe fn new_unchecked<I, S>(identifier_authority: I, sub_authorities: S) -> Self
    where
        I: Into<SidIdentifierAuthority>,
        S: AsRef<[u32]>,
    {
        // SAFETY: Forwarding the caller's unchecked constructor precondition.
        unsafe { SecurityIdentifier::new_unchecked(identifier_authority, sub_authorities).into() }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Unwrap is acceptable in tests")]
mod tests {
    use super::OwnedSid;
    use crate::{InvalidSidParts, SidIdentifierAuthority, StackSid, well_known};

    fn try_new_owned_sid<T: OwnedSid>() {
        let sid = T::try_new(SidIdentifierAuthority::NT_AUTHORITY, [32, 544]).unwrap();
        assert_eq!(sid.as_ref(), well_known::BUILTIN_ADMINISTRATORS.as_sid());
    }

    fn try_new_validates_sub_authority_count<T: OwnedSid>() {
        assert!(matches!(
            T::try_new(SidIdentifierAuthority::NT_AUTHORITY, []),
            Err(InvalidSidParts::MissingSubAuthority)
        ));
        assert!(T::try_new(SidIdentifierAuthority::NT_AUTHORITY, [0; 15]).is_ok());
        assert!(matches!(
            T::try_new(SidIdentifierAuthority::NT_AUTHORITY, [0; 16]),
            Err(InvalidSidParts::TooManySubAuthorities { count: 16, max: 15 })
        ));
    }

    #[cfg(all(windows, feature = "std"))]
    fn clone_sid_from_raw_copies_as<T: OwnedSid>(source: &crate::Sid) {
        // SAFETY: `source.as_raw()` remains valid for the duration of the call.
        let cloned = unsafe { T::clone_sid_from_raw(source.as_raw()) };

        assert_eq!(cloned.as_ref(), source);
        assert!(!core::ptr::addr_eq(cloned.as_ref(), source));
    }

    #[test]
    fn stack_sid_try_new_builds_owned_sid() {
        try_new_owned_sid::<StackSid>();
    }

    #[test]
    fn stack_sid_try_new_validates_sub_authority_count() {
        try_new_validates_sub_authority_count::<StackSid>();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn security_identifier_try_new_builds_owned_sid() {
        use crate::SecurityIdentifier;

        try_new_owned_sid::<SecurityIdentifier>();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn security_identifier_try_new_validates_sub_authority_count() {
        use crate::SecurityIdentifier;

        try_new_validates_sub_authority_count::<SecurityIdentifier>();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn boxed_sid_try_new_builds_owned_sid() {
        use crate::Sid;
        use std::boxed::Box;

        try_new_owned_sid::<Box<Sid>>();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn boxed_sid_try_new_validates_sub_authority_count() {
        use crate::Sid;
        use std::boxed::Box;

        try_new_validates_sub_authority_count::<Box<Sid>>();
    }

    #[cfg(all(windows, feature = "std"))]
    #[test]
    fn clone_sid_from_raw_copies_into_independent_storage() {
        use crate::{SecurityIdentifier, Sid};
        use std::boxed::Box;

        let source = well_known::BUILTIN_ADMINISTRATORS.as_sid();

        clone_sid_from_raw_copies_as::<StackSid>(source);
        clone_sid_from_raw_copies_as::<SecurityIdentifier>(source);
        clone_sid_from_raw_copies_as::<Box<Sid>>(source);
    }
}
