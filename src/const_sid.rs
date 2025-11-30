#[cfg(feature = "alloc")]
use crate::SecurityIdentifier;
#[cfg(not(has_ptr_metadata))]
use crate::polyfills_ptr::{from_raw_parts, from_raw_parts_mut};
use crate::{Sid, SidIdentifierAuthority, StackSid, internal::SidLenValid};
#[cfg(all(feature = "alloc", not(feature = "std")))]
use ::alloc::borrow::ToOwned;
#[cfg(has_ptr_metadata)]
use core::ptr::{from_raw_parts, from_raw_parts_mut};
use core::{
    array::TryFromSliceError,
    fmt::{self, Display},
    hash::{self, Hash},
    ptr,
};
#[cfg(feature = "std")]
use std::borrow::ToOwned;

/// Fixed-size, compile-time Security Identifier (SID).
///
/// `ConstSid<N>` stores the SID header plus exactly `N` sub-authorities as a
/// fixed-size array, making it usable in `const` contexts and suitable for
/// static embeddings. It can be viewed as a dynamically-sized [`Sid`] via
/// `AsRef<Sid>` or `as_sid()`, converted to an owning [`SecurityIdentifier`], or created from
/// an existing [Sid] when the sub-authority count matches `N`.
///
/// # Invariants
/// - `sub_authority_count == N` at all times.
/// - `N` must be within the valid Windows range for SIDs (1..=15).
///
/// # Examples
/// ```rust
/// # use win_security_identifier::{ConstSid, well_known, SidIdentifierAuthority, SecurityIdentifier};
/// const ADMIN_ALIAS: ConstSid<2> = well_known::BUILTIN_ADMINISTRATORS;
/// assert_eq!(ADMIN_ALIAS.to_string(), "S-1-5-32-544");
/// // It can be converted from (if const is correct) and to owned.
/// let owned: SecurityIdentifier = ADMIN_ALIAS.into();
/// assert_eq!(owned.to_string(), ADMIN_ALIAS.to_string());
/// assert_eq!(owned, ADMIN_ALIAS);
/// assert_eq!(ConstSid::<2>::try_from(owned.as_ref()).unwrap(), ADMIN_ALIAS);
/// assert!(ConstSid::<3>::try_from(owned).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ConstSid<const N: usize>
where
    [u32; N]: SidLenValid,
{
    /// SID revision (commonly `1`).
    pub revision: u8,
    // Always equals N; kept private to preserve invariant.
    sub_authority_count: u8,
    /// 6-byte identifier authority.
    pub identifier_authority: SidIdentifierAuthority,
    /// Fixed-size list of sub-authorities.
    pub sub_authority: [u32; N],
}

impl<const N: usize> AsRef<Sid> for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn as_ref(&self) -> &Sid {
        self.as_sid()
    }
}

impl<const N: usize> ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    /// Creates a new `ConstSid<N>` after validating the sub-authority count.
    ///
    /// Returns `None` if `N` is outside the valid Windows range (1..=15).
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{ConstSid, SidIdentifierAuthority};
    /// let s = ConstSid::<2>::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 544]);
    /// assert_eq!(s.to_string(), "S-1-5-32-544")
    #[must_use]
    #[inline]
    pub const fn new(
        identifier_authority: SidIdentifierAuthority,
        sub_authority: [u32; N],
    ) -> Self {
        Self {
            revision: 1,
            #[expect(
                clippy::cast_possible_truncation,
                reason = "N is guaranteed to be lower than 256 because it is lower than 16"
            )]
            sub_authority_count: N as u8,
            sub_authority,
            identifier_authority,
        }
    }

    /// Returns a reference to this `ConstSid` as a dynamically-sized [`Sid`].
    ///
    /// This allows treating the fixed-size `ConstSid` as a regular `Sid`
    /// with a trailing slice of sub-authorities.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{well_known, Sid};
    /// let sid: &Sid = well_known::BUILTIN_ADMINISTRATORS.as_sid();
    /// assert_eq!(sid.to_string(), "S-1-5-32-544");
    /// ```
    #[inline]
    #[must_use]
    pub const fn as_sid(&self) -> &Sid {
        // SAFETY: We construct a fat pointer to `Sid` with metadata `N` that
        // matches `sub_authority.len()`. The header layout is compatible
        // (`repr(C)`), and the trailing slice length equals N.
        unsafe { &*from_raw_parts(ptr::from_ref(self).cast::<()>(), N) }
    }

    /// Returns a mut reference to this `ConstSid` as a dynamically-sized [`Sid`].
    ///
    /// This allows treating the fixed-size `ConstSid` as a regular `Sid`
    /// with a trailing slice of sub-authorities.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{ConstSid, Sid, SidIdentifierAuthority};
    /// #
    /// // Create a mutable ConstSid with three sub-authorities:
    /// // S-1-5-21-1000 (revision 1, authority 5, sub-authorities [21, 1000])
    /// let mut cs = ConstSid::<3>::new(
    ///     SidIdentifierAuthority::NT_AUTHORITY,
    ///     [21u32, 100u32, 0u32],
    /// );
    ///
    /// // Get a mutable `&mut Sid` referencing the same memory.
    /// // From here we can mutate sub-authorities in-place without re-allocating.
    /// let sid_mut: &mut Sid = cs.as_sid_mut();
    ///
    /// // Modify the last sub-authority in-place.
    /// // (Assumes the `Sid` type exposes a mutable slice accessor.)
    /// sid_mut.identifier_authority = SidIdentifierAuthority::NULL_AUTHORITY;
    ///
    /// // The string representation reflects the in-place change.
    /// assert_eq!(sid_mut.to_string(), "S-1-0-21-100-0");
    /// ```
    #[inline]
    pub const fn as_sid_mut(&mut self) -> &mut Sid {
        // Safety: We construct a fat pointer to `Sid` with metadata `N` that
        // matches `sub_authority.len()`. The header layout is compatible
        // (`repr(C)`), and the trailing slice length equals N.
        unsafe { &mut *from_raw_parts_mut(ptr::from_mut(self).cast::<()>(), N) }
    }

    /// Returns the raw binary representation of this `ConstSid` as a byte slice.
    ///
    /// The returned slice contains the full in-memory layout of the SID,
    /// including header and sub-authorities, in the same format as used by Windows.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{ConstSid, SidIdentifierAuthority};
    /// const ADMIN: ConstSid<2> = ConstSid::new(
    ///     SidIdentifierAuthority::NT_AUTHORITY,
    ///     [32, 544],
    /// );
    /// let bytes = ADMIN.as_bytes();
    /// // First byte is the revision
    /// assert_eq!(bytes[0], 1);
    /// // Identifier authority is NT (5)
    /// assert_eq!(bytes[7], 5);
    /// // SubAuthorities: 32 (0x20 0x00 0x00 0x00) and 544 (0x20 0x02 0x00 0x00)
    /// assert_eq!(&bytes[8..12], &[32, 0, 0, 0]);
    /// assert_eq!(&bytes[12..16], &[32, 2, 0, 0]);
    /// ```
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        let binary_ptr = ptr::from_ref(self).cast::<u8>();
        // Safety: The layout of `ConstSid` is known and stable, and we are
        // creating a slice from a pointer to the start of the structure.
        unsafe { core::slice::from_raw_parts(binary_ptr, size_of::<Self>()) }
    }

    /// Returns the last sub-authority value (Relative Identifier, or RID) of this [`ConstSid`].
    ///
    /// The RID is commonly used to identify a specific user, group, or entity within a domain,
    /// and is the last element in the sub-authority array.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{ConstSid, SidIdentifierAuthority};
    /// let sid = ConstSid::<2>::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 544]);
    /// assert_eq!(sid.rid(), 544);
    /// ```
    #[inline]
    #[must_use]
    pub const fn rid(&self) -> u32 {
        #[expect(
            clippy::indexing_slicing,
            reason = "N is guaranteed to be greater than 0"
        )]
        self.sub_authority[N - 1]
    }
}

impl<const N: usize> PartialEq<Sid> for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn eq(&self, other: &Sid) -> bool {
        self.as_sid().eq(other)
    }
}

impl<const N: usize> PartialEq<ConstSid<N>> for Sid
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn eq(&self, other: &ConstSid<N>) -> bool {
        self.eq(other.as_sid())
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> PartialEq<SecurityIdentifier> for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn eq(&self, other: &SecurityIdentifier) -> bool {
        self.eq(other.as_ref())
    }
}
#[cfg(feature = "alloc")]
impl<const N: usize> PartialEq<ConstSid<N>> for SecurityIdentifier
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn eq(&self, other: &ConstSid<N>) -> bool {
        self.eq(other.as_sid())
    }
}

impl<const N: usize> PartialEq<ConstSid<N>> for StackSid
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn eq(&self, other: &ConstSid<N>) -> bool {
        self.as_sid().eq(other)
    }
}

impl<const N: usize> PartialEq<StackSid> for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn eq(&self, other: &StackSid) -> bool {
        self.as_sid().eq(other)
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> From<ConstSid<N>> for SecurityIdentifier
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn from(value: ConstSid<N>) -> Self {
        let sid: &Sid = value.as_ref();
        sid.to_owned()
    }
}

impl<const N: usize> TryFrom<&Sid> for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    type Error = TryFromSliceError;
    #[inline]
    fn try_from(value: &Sid) -> Result<Self, Self::Error> {
        let revision = value.revision;
        let identifier_authority = value.identifier_authority;
        let sub_authority: [u32; N] = value.get_sub_authorities().try_into()?;
        Ok(Self {
            revision,
            identifier_authority,
            #[expect(
                clippy::cast_possible_truncation,
                reason = "N is guaranteed to be lower than 256 because it is lower than 16"
            )]
            sub_authority_count: N as u8,
            sub_authority,
        })
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> TryFrom<SecurityIdentifier> for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    type Error = TryFromSliceError;
    #[inline]
    fn try_from(value: SecurityIdentifier) -> Result<Self, Self::Error> {
        Self::try_from(value.as_sid())
    }
}

impl<const N: usize> Display for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_sid())
    }
}

impl<const N: usize> Hash for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.revision.hash(state);
        self.sub_authority_count.hash(state);
        self.identifier_authority.hash(state);
        Hash::hash_slice(&self.sub_authority[..], state);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Unwrap is not an issue in test")]
#[allow(clippy::expect_used, reason = "Expect is not an issue in test")]
mod test {
    use super::*;
    #[cfg(feature = "std")]
    #[test]
    pub fn test_hash() {
        use core::hash::{Hash, Hasher};
        use std::hash::DefaultHasher;

        use crate::well_known;
        let sid = well_known::LOCAL_SYSTEM;
        let mut hasher1 = DefaultHasher::default();
        let mut hasher2 = DefaultHasher::default();
        sid.hash(&mut hasher1);
        sid.as_ref().hash(&mut hasher2);
        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[cfg(feature = "alloc")]
    #[allow(clippy::unwrap_used, reason = "Unwrap is not an issue in test")]
    #[test]
    fn test_layout_matches_sid() {
        use crate::SidSizeInfo;
        use core::alloc::Layout;
        let size = SidSizeInfo::from_count(1).unwrap();
        let layout = size.get_layout();
        assert_eq!(Layout::new::<ConstSid<1>>(), layout);
    }
    #[cfg(feature = "macro")]
    #[test]
    fn test_parsing() {
        use crate::{sid, well_known};
        let sid = sid!("S-1-5-32-544");
        let expected_sid = well_known::BUILTIN_ADMINISTRATORS;
        assert_eq!(sid, expected_sid);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_display_and_eq() {
        use crate::well_known;

        let formatted = "S-1-5-32-544";
        let expected_sid: SecurityIdentifier = formatted.parse().unwrap();
        let sid = well_known::BUILTIN_ADMINISTRATORS;
        assert_eq!(sid, expected_sid);
        assert_eq!(sid.to_string(), formatted);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_try_from_sid_and_security_identifier() {
        let sid = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [21, 42]);
        let owned: SecurityIdentifier = sid.into();
        let sid2 = ConstSid::<2>::try_from(owned.as_ref()).unwrap();
        assert_eq!(sid, sid2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_invalid_try_from() {
        let sid = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [21, 42, 99]);
        let owned: SecurityIdentifier = sid.into();
        assert!(ConstSid::<2>::try_from(owned.as_ref()).is_err());
    }

    #[test]
    fn test_const_sid_macro() {
        let sid = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [32, 544]);
        assert_eq!(sid.revision, Sid::REVISION);
        assert_eq!(
            sid.identifier_authority,
            SidIdentifierAuthority::NT_AUTHORITY
        );
        assert_eq!(sid.sub_authority, [32, 544]);
    }
}
