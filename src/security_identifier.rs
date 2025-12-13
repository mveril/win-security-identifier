pub use crate::InvalidSidFormat;
use crate::Sid;
use crate::SidIdentifierAuthority;
use crate::SidSizeInfo;
use crate::StackSid;
use crate::utils;
use crate::utils::sub_authority_size_guard;
use crate::utils::validate_sid_bytes_unaligned;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use ::alloc::{borrow::ToOwned, boxed::Box};
use core::alloc::Layout;
use core::fmt::{self, Debug, Display};
use core::mem::offset_of;
use core::ops::Deref;
mod maybe_uninit;
use core::borrow::{Borrow, BorrowMut};
use core::ops::DerefMut;
use core::ptr;
use core::str::FromStr;
use delegate::delegate;
use maybe_uninit::MaybeUninitSecurityIdentifier;
use parsing::SidComponents;
#[cfg(feature = "std")]
use std::borrow::ToOwned;

/// Owned, heap-allocated Windows **Security Identifier** (SID).
///
/// This type owns the underlying SID memory and guarantees:
/// - Proper allocation according to the number of sub-authorities.
/// - Proper deallocation via `Drop`.
/// - Safe read/write access through `Deref`/`DerefMut` to the inner [Sid].
///
/// It can be constructed from raw parts, parsed from text, cloned,
/// or retrieved from the current user's access token (Windows-only).
///
///
/// # Examples
/// ```rust
/// # use win_security_identifier::{SecurityIdentifier, SidIdentifierAuthority};
/// // Build a SID S-1-5-32-544 (Builtin\Administrators) from parts:
/// let ia = SidIdentifierAuthority::NT_AUTHORITY; // example ctor
/// let subs = [32u32, 544u32];
/// let sid = SecurityIdentifier::try_new(ia, &subs)
///     .expect("valid SID parts");
/// println!("{}", sid); // e.g., "S-1-5-32-544"
/// ```
pub struct SecurityIdentifier {
    inner: Box<Sid>,
}

impl Debug for SecurityIdentifier {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        utils::debug_print::<Self>(stringify!(SecurityIdentifier), self, f)
    }
}

impl SecurityIdentifier {
    /// Creates a new `SecurityIdentifier` from parts, validating input.
    ///
    /// Returns `None` if `sub_authority` length is out of bounds (not in 1..=15).
    ///
    /// # Parameters
    /// - `identifier_authority`: High-level authority (e.g. `NT_AUTHORITY`).
    /// - `sub_authority`: Slice of sub-authorities (1..=15 elements).
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, SidIdentifierAuthority};
    /// let sid = SecurityIdentifier::try_new(
    ///     SidIdentifierAuthority::NT_AUTHORITY,
    ///     [32u32, 544u32]
    /// ).unwrap();
    /// assert_eq!(sid.revision, 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.get_sub_authorities(), [32u32, 544u32]);
    /// ```
    #[must_use]
    #[inline]
    pub fn try_new<I: Into<SidIdentifierAuthority>, S: AsRef<[u32]>>(
        identifier_authority: I,
        sub_authority: S,
    ) -> Option<Self> {
        let sub_authority = sub_authority.as_ref();
        // SAFETY: sub_authority_count is correctly validated by guard.
        sub_authority_size_guard(sub_authority.len())
            .then_some(unsafe { Self::new_unchecked(identifier_authority, sub_authority) })
    }

    /// Creates a new `SecurityIdentifier` from parts **without validation**.
    ///
    /// # Safety
    /// - Caller must ensure `sub_authority` length is in `1..=15`.
    /// - `identifier_authority` must be a valid Windows authority.
    ///
    /// Violating these preconditions results in undefined behavior or later panics.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, SidIdentifierAuthority};
    /// let sid = unsafe {
    ///     SecurityIdentifier::new_unchecked(
    ///         SidIdentifierAuthority::NT_AUTHORITY,
    ///         [32u32, 544u32],
    ///     )
    /// };
    /// assert_eq!(sid.revision, 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.get_sub_authorities(), [32u32, 544u32]);
    /// ```
    #[must_use]
    #[inline]
    pub unsafe fn new_unchecked<I: Into<SidIdentifierAuthority>, S: AsRef<[u32]>>(
        identifier_authority: I,
        sub_authority: S,
    ) -> Self {
        let sub_authority = sub_authority.as_ref();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Precondition of sub_authority_is_checked in the doc."
        )]
        let sub_authority_count = sub_authority.len() as u8;
        let identifier_authority = identifier_authority.into();
        // SAFETY: sub_authority_count is validated by guard.
        let size_info = unsafe { SidSizeInfo::from_count(sub_authority_count).unwrap_unchecked() };
        // Safety: The uninit SID will be correctly filled after.
        let mut uninit = MaybeUninitSecurityIdentifier::alloc(&size_info);
        let sid_ptr = uninit.as_mut_ptr();
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "Same kind of operations"
        )]
        // Safety: We know the ptr is not null so we can write
        unsafe {
            (*sid_ptr).revision = Sid::REVISION;
            (*sid_ptr).sub_authority_count = sub_authority_count;
            (*sid_ptr).identifier_authority = identifier_authority;
            (*sid_ptr).sub_authority.copy_from_slice(sub_authority);
        }
        // Safety: all is written so we can assume init
        unsafe { uninit.assume_init() }
    }

    /// Creates a `SecurityIdentifier` from a byte slice.
    ///
    /// This function attempts to parse a byte slice into a valid `SecurityIdentifier`.
    ///
    /// # Parameters
    /// - `bytes`: A type that can be referenced as a byte slice (`AsRef<[u8]>`).
    ///
    /// # Errors
    /// - [`InvalidSidFormat`] If the byte slice is not a valid SID format.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, InvalidSidFormat};
    /// // SID: S-1-5-32-544 (Administrators)
    /// let bytes: [u8; 16] = [
    ///     1,    // Revision
    ///     2,    // SubAuthorityCount
    ///     0, 0, 0, 0, 0, 5, // IdentifierAuthority = NT AUTHORITY
    ///     32, 0, 0, 0,      // SubAuthority[0] = 32
    ///     32, 2, 0, 0       // SubAuthority[1] = 544 (0x220 little endian)
    /// ];
    /// let sid = SecurityIdentifier::from_bytes(&bytes);
    /// assert!(sid.is_ok());
    /// assert!(sid.unwrap().to_string() == "S-1-5-32-544")
    /// ```
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidSidFormat> {
        validate_sid_bytes_unaligned(bytes)?;
        // SAFETY: All check was done before
        Ok(unsafe { Self::from_bytes_unchecked(bytes) })
    }

    /// Builds a `SecurityIdentifier` from raw bytes without validation.
    ///
    /// # Safety
    /// The caller must ensure `bytes` encodes a valid SID, with a length that
    /// matches the embedded `sub_authority_count` and the expected binary
    /// layout. Passing invalid bytes results in undefined behavior.
    #[inline]
    unsafe fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        // SAFETY: All safety criteron are described in the doc
        let size_info = unsafe {
            #[expect(
                clippy::indexing_slicing,
                reason = "It's the unchecked version safety is precised in the doc."
            )]
            SidSizeInfo::from_count(bytes[offset_of!(Sid, sub_authority_count)]).unwrap_unchecked()
        };
        // Safety: The uninit SID is properly initialized by copying from `self` after.
        let mut uninit = MaybeUninitSecurityIdentifier::alloc(&size_info);
        // Safety: We copy all the bytes from a valid SID of the same size.
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                uninit.as_mut_ptr().cast::<u8>(),
                size_info.get_layout().size(),
            );
        }
        // Safety: all is written so we can init.
        unsafe { uninit.assume_init() }
    }

    /// Returns a reference to this `SecurityIdentifier` as a dynamically-sized [`Sid`].
    ///
    /// This allows treating owned `SecurityIdentifier` as a regular `Sid`
    /// with a trailing slice of sub-authorities.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, SidIdentifierAuthority, Sid};
    /// let admin = SecurityIdentifier::try_new(
    ///     SidIdentifierAuthority::NT_AUTHORITY,
    ///     [32, 544],
    /// ).unwrap();
    /// let sid: &Sid = admin.as_sid();
    /// assert_eq!(sid.to_string(), "S-1-5-32-544");
    /// ```
    #[inline]
    #[must_use]
    pub fn as_sid(&self) -> &Sid {
        self.inner.as_ref()
    }

    /// Returns a mut reference to this `SecurityIdentifier` as a dynamically-sized [`Sid`].
    ///
    /// This allows treating owned `SecurityIdentifier` as a regular `Sid`
    /// with a trailing slice of sub-authorities.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, Sid, SidIdentifierAuthority};
    /// #
    /// // Create a mutable ConstSid with three sub-authorities:
    /// // S-1-5-21-1000 (revision 1, authority 5, sub-authorities [21, 1000])
    /// let mut owned = SecurityIdentifier::try_new(
    ///     SidIdentifierAuthority::NT_AUTHORITY,
    ///     &[21u32, 100u32, 0u32],
    /// ).unwrap();
    ///
    /// // Get a mutable `&mut Sid` referencing the same memory.
    /// // From here we can mutate sub-authorities in-place without re-allocating.
    /// let sid_mut: &mut Sid = owned.as_sid_mut();
    ///
    /// // Modify the last sub-authority in-place.
    /// // (Assumes the `Sid` type exposes a mutable slice accessor.)
    /// sid_mut.identifier_authority = SidIdentifierAuthority::NULL_AUTHORITY;
    ///
    /// // The string representation reflects the in-place change.
    /// assert_eq!(sid_mut.to_string(), "S-1-0-21-100-0");
    /// ```
    #[inline]
    pub fn as_sid_mut(&mut self) -> &mut Sid {
        self.inner.as_mut()
    }
}

impl TryFrom<&[u8]> for SecurityIdentifier {
    type Error = InvalidSidFormat;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl<'a> From<&'a Sid> for SecurityIdentifier {
    #[inline]
    fn from(value: &'a Sid) -> Self {
        let binary = value.as_binary();
        // Safety: sub_authority_count is known to be valid because `self` is valid.
        unsafe { Self::from_bytes_unchecked(binary) }
    }
}

impl FromStr for SecurityIdentifier {
    type Err = InvalidSidFormat;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let components = SidComponents::from_str(s)?;
        Ok(
            // SAFETY: sub_authority_count is known to be valid because `SidComponents::from_str` validated it.
            unsafe {
                Self::new_unchecked(
                    components.identifier_authority,
                    components.sub_authority.as_slice(),
                )
            },
        )
    }
}

impl ToOwned for Sid {
    type Owned = super::SecurityIdentifier;
    #[inline]
    fn to_owned(&self) -> Self::Owned {
        self.into()
    }
}

impl Borrow<Sid> for SecurityIdentifier {
    #[inline]
    fn borrow(&self) -> &Sid {
        self.as_sid()
    }
}

impl BorrowMut<Sid> for SecurityIdentifier {
    #[inline]
    fn borrow_mut(&mut self) -> &mut Sid {
        self.as_sid_mut()
    }
}

impl Deref for SecurityIdentifier {
    type Target = Sid;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for SecurityIdentifier {
    delegate!(
        to self.inner {
            #[inline]
            fn deref_mut(&mut self) -> &mut Sid;
        }
    );
}

impl AsRef<Sid> for SecurityIdentifier {
    delegate! {
        to self.inner {
            #[inline]
            fn as_ref(&self) -> &Sid;
        }
    }
}

impl AsMut<Sid> for SecurityIdentifier {
    delegate! {
        to self.inner {
            #[inline]
            fn as_mut(&mut self) -> &mut Sid;
        }
    }
}

impl Clone for SecurityIdentifier {
    #[inline]
    fn clone(&self) -> Self {
        self.as_sid().into()
    }
    #[inline]
    fn clone_from(&mut self, source: &Self) {
        if Layout::for_value(self.as_sid()) == Layout::for_value(source.as_sid()) {
            // Safety: We checked layout is ok
            unsafe {
                self.as_binary_mut().copy_from_slice(source.as_binary());
            }
        } else {
            *self = source.clone();
        }
    }
}

impl Display for SecurityIdentifier {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&*self.inner, f)
    }
}

impl Eq for SecurityIdentifier {}

impl PartialEq<Sid> for SecurityIdentifier {
    #[inline]
    fn eq(&self, other: &Sid) -> bool {
        AsRef::<Sid>::as_ref(self) == other
    }
}

impl PartialEq<SecurityIdentifier> for Sid {
    #[inline]
    fn eq(&self, other: &SecurityIdentifier) -> bool {
        self == other.as_ref()
    }
}

impl PartialEq<StackSid> for SecurityIdentifier {
    #[inline]
    fn eq(&self, other: &StackSid) -> bool {
        self == other.as_sid()
    }
}

impl PartialEq<SecurityIdentifier> for StackSid {
    #[inline]
    fn eq(&self, other: &SecurityIdentifier) -> bool {
        self == other.as_sid()
    }
}

impl PartialEq for SecurityIdentifier {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        AsRef::<Sid>::as_ref(self) == other.as_ref()
    }
}

impl From<Box<Sid>> for SecurityIdentifier {
    #[inline]
    fn from(value: Box<Sid>) -> Self {
        Self { inner: value }
    }
}

impl From<SecurityIdentifier> for Box<Sid> {
    #[inline]
    fn from(value: SecurityIdentifier) -> Self {
        value.inner
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Unwrap is not an issue in test")]
#[allow(clippy::expect_used, reason = "Expect is not an issue in test")]
pub mod test {
    use super::super::SecurityIdentifier;
    use super::super::Sid;
    use super::super::sid_identifier_authority::test::arb_identifier_authority;
    #[cfg(not(has_ptr_metadata))]
    use crate::polyfills_ptr::metadata;
    use crate::well_known;
    use core::hash::Hash;
    use core::hash::Hasher;
    #[cfg(has_ptr_metadata)]
    use core::ptr::metadata;
    use proptest::prelude::*;
    pub fn arb_security_identifier() -> impl Strategy<Value = SecurityIdentifier> {
        (
            arb_identifier_authority(),
            proptest::collection::vec(any::<u32>(), 1..=15),
        )
            .prop_map(|(identifier_authority, sub_authorities)| {
                let subs = &sub_authorities.as_slice();
                SecurityIdentifier::try_new(identifier_authority, subs)
                    .expect("Failed to generate SecurityIdentifier")
            })
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn test_sid_properties(security_identifier in arb_security_identifier()) {
            // Hash
            use std::collections::hash_map::DefaultHasher;
            // Test access to inner Sid
            let sid: &Sid = security_identifier.as_ref();

            // Check length of sub_authorities
            assert_eq!(sid.get_sub_authorities().len(), sid.sub_authority_count as usize);

            // Display format: commence par S-1-
            let disp = format!("{sid}");
            prop_assert!(disp.starts_with("S-1-"), "Display doesn't start with S-1- : {}", disp);

            // ToOwned et Eq
            let owned_sid = sid.to_owned();
            let sid2 = &*owned_sid;
            prop_assert_eq!(sid, sid2, "to_owned then deref should yield eq sids");

            let mut h1 = DefaultHasher::new();
            sid.hash(&mut h1);
            let mut h2 = DefaultHasher::new();
            sid2.hash(&mut h2);
            prop_assert_eq!(h1.finish(), h2.finish(), "Hashes should match for equal SIDs");
        }

        #[test]
        #[cfg(feature="std")]
        fn test_securityidentifier_eq_and_hash(a in arb_security_identifier(), b in arb_security_identifier()) {
            // Reflexivity
            prop_assert_eq!(&*a, &*a);

            // Hash: equal => hash equal
            if *a == *b {
                let mut ha = std::collections::hash_map::DefaultHasher::new();
                let mut hb = std::collections::hash_map::DefaultHasher::new();
                a.hash(&mut ha);
                b.hash(&mut hb);
                prop_assert_eq!(ha.finish(), hb.finish(), "Hashes must be equal for identical SIDs");
            }
        }

        #[test]
        fn test_sub_authority_slice_bounds(security_identifier in arb_security_identifier()) {
            let sid: &Sid = &security_identifier;
            let subs = sid.get_sub_authorities();
            assert!(!subs.is_empty() && subs.len() <= 15, "sub_authorities length must be in 1..=15");
        }

         #[test]
        fn test_ptr_metadata(security_identifier in arb_security_identifier()) {
            let sid: &Sid = &security_identifier;
            prop_assert_eq!(sid.sub_authority_count as usize, sid.get_sub_authorities().len());
            prop_assert_eq!(sid.sub_authority_count as usize, metadata(sid));
        }

        #[test]
        #[cfg(feature="std")]
        fn test_sid_to_string_from_string(sid1 in arb_security_identifier()){
            let sid2: SecurityIdentifier = sid1.to_string().parse().unwrap();
            prop_assert_eq!(sid1, sid2);
        }

        fn test_security_identifier_clone(sid in arb_security_identifier()){
            prop_assert_eq!(sid.clone(), sid);

        }

        #[test]
        fn test_security_identifier_clone_from(mut sid in arb_security_identifier(), sid_source in arb_security_identifier()){
            sid.clone_from(&sid_source);
            prop_assert_eq!(sid, sid_source);
        }
    }

    #[cfg(all(feature = "std", windows))]
    mod windows {
        use core::ptr;
        use core::slice;

        use crate::GetCurrentSid as _;
        use crate::SecurityIdentifier;

        use super::arb_security_identifier;
        use proptest::prelude::*;
        use windows_sys::Win32::Security::*;

        proptest! {
            #[test]
            fn test_init_sid_matches_rust_bytes(sid in arb_security_identifier()) {
                let subauth = sid.get_sub_authorities();
                #[expect(clippy::cast_possible_truncation, reason="No truncation here because of range of subathority is between 1-15")]
                let n = subauth.len() as u8;
                // SAFETY: GetSidLengthRequired is safe for sid Length
                let required_size = unsafe { GetSidLengthRequired(n) } as usize;
                let mut buffer = vec![0u8; required_size];
                #[expect(clippy::cast_ptr_alignment, reason = "Unaligned pointer is not an issue for windows API")]
                let sid_ptr = buffer.as_mut_ptr().cast::<SID>();
                // SAFETY: InitializeSid is ok with the good buffer.
                #[expect(clippy::multiple_unsafe_ops_per_block, reason="Not realy an issue in tests")]
                unsafe {
                    let ok = InitializeSid(
                        sid_ptr.cast(),
                        ptr::from_ref(&sid.identifier_authority).cast::<SID_IDENTIFIER_AUTHORITY>(),
                        n,
                    );
                    prop_assert!(ok != 0, "InitializeSid failed");

                    for (i, &sa) in subauth.iter().enumerate() {
                        let ptr = GetSidSubAuthority(sid_ptr.cast(), u32::try_from(i).unwrap());
                        prop_assert!(!ptr.is_null(), "GetSidSubAuthority null at index {}", i);
                        *ptr = sa;
                    }

                    let win_len = GetLengthSid(sid_ptr.cast());
                    let win_bytes = slice::from_raw_parts(sid_ptr as *const u8, win_len as usize);

                    let rust_bytes = sid.as_binary();
                    prop_assert_eq!(
                        win_bytes,
                        rust_bytes,
                        "The Windows SID must match the binary Rust SID."
                    );
                }
            }
        }

        #[test]
        fn test_current_sid_work() {
            let result = SecurityIdentifier::get_current_user_sid();
            assert!(
                result.is_ok(),
                "Failed to get current user SID: {:?}",
                result.err()
            );
            let sid = result.unwrap();
            // Safety: this method are always safe to call.
            #[expect(clippy::multiple_unsafe_ops_per_block, reason = "allowed in tests")]
            let result = unsafe {
                (IsValidSid(sid.as_raw()) == 0)
                    .then_some(windows_sys::Win32::Foundation::GetLastError())
            };
            assert_eq!(result, None, "SID is not valid: {result:?}");
        }
    }
    #[test]
    fn test_debug() {
        let sample_sid = well_known::NULL;
        assert_eq!(
            format!("{:?}", SecurityIdentifier::from(sample_sid.as_sid())),
            format!("{:}(S-1-0-0)", stringify!(SecurityIdentifier)),
        );
    }
}
