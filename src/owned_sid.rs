use crate::{InvalidSidParts, Sid, SidIdentifierAuthority, StackSid};

#[cfg(feature = "alloc")]
use crate::SecurityIdentifier;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::boxed::Box;
#[cfg(all(feature = "alloc", feature = "std"))]
use std::boxed::Box;

/// A type that owns SID storage and can construct an independent SID value.
///
/// # Invariants
/// Implementations are sealed so the crate can guarantee that every value owns
/// a valid SID whose authority and sub-authorities exactly match its constructor
/// input. Values never borrow from or retain pointers into constructor inputs,
/// and the SID returned by [`AsRef`] remains valid for the lifetime of the
/// owned value.
#[allow(
    private_bounds,
    reason = "OwnedSid is intentionally sealed to preserve its ownership invariants"
)]
pub trait OwnedSid: private::Sealed + AsRef<Sid> + Sized + for<'a> From<&'a Sid> {
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
}

mod private {
    use super::StackSid;
    #[cfg(feature = "alloc")]
    use super::{Box, SecurityIdentifier, Sid};

    pub trait Sealed {}

    impl Sealed for StackSid {}
    #[cfg(feature = "alloc")]
    impl Sealed for SecurityIdentifier {}
    #[cfg(feature = "alloc")]
    impl Sealed for Box<Sid> {}
}

impl OwnedSid for StackSid {
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

#[cfg(feature = "alloc")]
impl OwnedSid for SecurityIdentifier {
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

#[cfg(feature = "alloc")]
impl OwnedSid for Box<Sid> {
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

    fn from_sid_copies_as<T: OwnedSid>(source: &crate::Sid) {
        let cloned = T::from(source);

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

    #[test]
    fn stack_sid_from_sid_copies_into_independent_storage() {
        from_sid_copies_as::<StackSid>(well_known::BUILTIN_ADMINISTRATORS.as_sid());
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
    fn heap_owned_sids_from_sid_copy_into_independent_storage() {
        use crate::{SecurityIdentifier, Sid};
        use std::boxed::Box;

        let source = well_known::BUILTIN_ADMINISTRATORS.as_sid();
        from_sid_copies_as::<SecurityIdentifier>(source);
        from_sid_copies_as::<Box<Sid>>(source);
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
}
