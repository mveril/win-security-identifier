#[cfg(feature = "alloc")]
use crate::SecurityIdentifier;
#[cfg(not(has_ptr_metadata))]
use crate::polyfils_ptr::from_raw_parts;
use crate::{Sid, SidIdentifierAuthority, internal::SidLenValid};
#[cfg(all(feature = "alloc", not(feature = "std")))]
use ::alloc::borrow::ToOwned;
#[cfg(feature = "alloc")]
use core::ops::Deref;
#[cfg(has_ptr_metadata)]
use core::ptr::from_raw_parts;
use core::{
    array::TryFromSliceError,
    fmt::{self, Display},
    hash::{self, Hash},
};
#[cfg(feature = "std")]
use std::borrow::ToOwned;

/// Fixed-size, compile-time Security Identifier (SID).
///
/// `ConstSid<N>` stores the SID header plus exactly `N` sub-authorities as a
/// fixed-size array, making it usable in `const` contexts and suitable for
/// static embeddings. It can be viewed as a dynamically-sized `Sid` via
/// `AsRef<Sid>`, converted to an owning `SecurityIdentifier`, or created from
/// an existing `Sid` when the sub-authority count matches `N`.
///
/// # Invariants
/// - `sub_authority_count == N` at all times.
/// - `N` must be within the valid Windows range for SIDs (1..=15).
///
/// # Examples
/// ```rust
/// # use win_security_identifier::{ConstSid, SidIdentifierAuthority, SecurityIdentifier};
/// const ADMIN_ALIAS: ConstSid<2> = ConstSid::new(
///     1,
///     SidIdentifierAuthority::nt_authority(),
///     [32, 544],
/// ).unwrap();
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
    fn as_ref(&self) -> &Sid {
        // SAFETY: We construct a fat pointer to `Sid` with metadata `N` that
        // matches `sub_authority.len()`. The header layout is compatible
        // (`repr(C)`), and the trailing slice length equals N.
        unsafe { &*from_raw_parts(self as *const Self as *mut Self as *mut (), N) }
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
    /// let s = ConstSid::<2>::new(1, SidIdentifierAuthority::nt_authority(), [32, 544]);
    /// assert!(s.is_some());
    /// ```
    #[must_use]
    pub const fn new(
        revision: u8,
        identifier_authority: SidIdentifierAuthority,
        sub_authority: [u32; N],
    ) -> Self {
        Self {
            revision,
            sub_authority_count: N as u8,
            sub_authority,
            identifier_authority,
        }
    }
}

impl<const N: usize> PartialEq<Sid> for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    fn eq(&self, other: &Sid) -> bool {
        self.as_ref().eq(other)
    }
}

impl<const N: usize> PartialEq<ConstSid<N>> for Sid
where
    [u32; N]: SidLenValid,
{
    fn eq(&self, other: &ConstSid<N>) -> bool {
        self.eq(other.as_ref())
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> PartialEq<SecurityIdentifier> for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    fn eq(&self, other: &SecurityIdentifier) -> bool {
        self.eq(other.as_ref())
    }
}
#[cfg(feature = "alloc")]
impl<const N: usize> PartialEq<ConstSid<N>> for SecurityIdentifier
where
    [u32; N]: SidLenValid,
{
    fn eq(&self, other: &ConstSid<N>) -> bool {
        self.eq(other.as_ref())
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> From<ConstSid<N>> for SecurityIdentifier
where
    [u32; N]: SidLenValid,
{
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

    fn try_from(value: &Sid) -> Result<Self, Self::Error> {
        let revision = value.revision;
        let identifier_authority = value.identifier_authority;
        let sub_authority: [u32; N] = value.get_sub_authorities().try_into()?;
        Ok(Self::new(revision, identifier_authority, sub_authority))
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> TryFrom<SecurityIdentifier> for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    type Error = TryFromSliceError;

    fn try_from(value: SecurityIdentifier) -> Result<Self, Self::Error> {
        let sid: &Sid = value.deref();
        Self::try_from(sid)
    }
}

impl<const N: usize> Display for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sid: &Sid = self.as_ref();
        Display::fmt(sid, f)
    }
}

impl<const N: usize> Hash for ConstSid<N>
where
    [u32; N]: SidLenValid,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.revision.hash(state);
        self.sub_authority_count.hash(state);
        self.identifier_authority.hash(state);
        Hash::hash_slice(&self.sub_authority[..], state);
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "std")]
    use super::*;
    #[cfg(feature = "std")]
    #[test]
    pub fn test_hash() {
        use std::hash::{DefaultHasher, Hash, Hasher};
        let sid = ConstSid::new(1, [1, 0, 0, 0, 0, 0].into(), [0; 1]);
        let mut hasher1 = DefaultHasher::default();
        let mut hasher2 = DefaultHasher::default();
        sid.hash(&mut hasher1);
        sid.as_ref().hash(&mut hasher2);
        assert_eq!(hasher1.finish(), hasher2.finish())
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_layout_matches_sid() {
        use core::alloc::Layout;

        use crate::SidSizeInfo;
        let size = SidSizeInfo {
            sub_authority_count: 1,
        };
        let layout = size.get_layout();
        assert_eq!(Layout::new::<ConstSid<1>>(), layout)
    }
}
