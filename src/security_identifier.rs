pub use crate::InvalidSidFormat;
use crate::Sid;
use crate::SidIdentifierAuthority;
use crate::SidSizeInfo;
#[cfg(not(has_ptr_metadata))]
use crate::polyfils_ptr::from_raw_parts_mut;
use crate::utils::sub_authority_size_guard;
#[cfg(has_ptr_metadata)]
use core::ptr::from_raw_parts_mut;
use parsing::SidComponents;
mod token_error;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use ::alloc::{alloc, borrow::Borrow, borrow::ToOwned};
use ::core::alloc::Layout;
use core::fmt::{self, Debug, Display};
#[cfg(all(windows, feature = "std"))]
use core::mem::MaybeUninit;
use core::ops::DerefMut;
use core::str::FromStr;
use core::{ops::Deref, ptr::NonNull};
#[cfg(feature = "std")]
use std::{alloc, borrow::Borrow, borrow::ToOwned};
pub use token_error::TokenError;
#[cfg(all(windows, feature = "std"))]
use windows_sys::Win32::Security::*;

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
/// let revision = 1u8;
/// let ia = SidIdentifierAuthority::NT_AUTHORITY; // example ctor
/// let subs = [32u32, 544u32];
/// let sid = SecurityIdentifier::try_new(revision, ia, &subs)
///     .expect("valid SID parts");
/// println!("{}", sid); // e.g., "S-1-5-32-544"
/// ```
pub struct SecurityIdentifier {
    sid: NonNull<Sid>,
    layout: Layout,
}

impl Debug for SecurityIdentifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.deref(), f)
    }
}

impl SecurityIdentifier {
    /// Creates a new `SecurityIdentifier` from parts, validating input.
    ///
    /// Returns `None` if `sub_authority` length is out of bounds (not in 1..=15).
    ///
    /// # Parameters
    /// - `revision`: SID revision (usually `1`).
    /// - `identifier_authority`: High-level authority (e.g. `NT_AUTHORITY`).
    /// - `sub_authority`: Slice of sub-authorities (1..=15 elements).
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, SidIdentifierAuthority};
    /// let sid = SecurityIdentifier::try_new(
    ///     1,
    ///     SidIdentifierAuthority::NT_AUTHORITY,
    ///     [32u32, 544u32]
    /// ).unwrap();
    /// assert_eq!(sid.revision, 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.get_sub_authorities(), [32u32, 544u32]);
    /// ```
    #[must_use]
    pub fn try_new<I: Into<SidIdentifierAuthority>, S: AsRef<[u32]>>(
        revision: u8,
        identifier_authority: I,
        sub_authority: S,
    ) -> Option<Self> {
        let sub_authority = sub_authority.as_ref();
        if sub_authority_size_guard(sub_authority.len()) {
            let sub_authority_count = sub_authority.len() as u8;
            let identifier_authority = identifier_authority.into();
            unsafe {
                // SAFETY: allocation size is computed from `SidSizeInfo` using
                // a validated sub-authority count.
                let mut instance =
                    Self::uninit(SidSizeInfo::from_count(sub_authority_count).unwrap());
                instance.sid.as_mut().revision = revision;
                instance.sid.as_mut().sub_authority_count = sub_authority_count;
                instance.sid.as_mut().identifier_authority = identifier_authority;
                instance
                    .sid
                    .as_mut()
                    .sub_authority
                    .copy_from_slice(sub_authority);
                Some(instance)
            }
        } else {
            None
        }
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
    ///         1,
    ///         SidIdentifierAuthority::NT_AUTHORITY,
    ///         [32u32, 544u32],
    ///     )
    /// };
    /// assert_eq!(sid.revision, 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.get_sub_authorities(), [32u32, 544u32]);
    /// ```
    pub unsafe fn new_unchecked<I: Into<SidIdentifierAuthority>, S: AsRef<[u32]>>(
        revision: u8,
        identifier_authority: I,
        sub_authority: S,
    ) -> Self {
        Self::try_new(revision, identifier_authority, sub_authority).unwrap()
    }

    /// Allocates uninitialized storage for a `Sid` using `size_info`.
    ///
    /// This is an internal building block used by constructors.
    ///
    /// # Safety
    /// - The returned memory is uninitialized; caller must initialize all
    ///   fields before any safe observation.
    /// - `size_info` must be consistent with the number of sub-authorities written later.
    unsafe fn uninit(size_info: SidSizeInfo) -> Self {
        let layout = size_info.get_layout();

        let mem_ptr = unsafe { alloc::alloc(layout) };
        if mem_ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }
        // SAFETY: `from_raw_parts_mut` builds a fat pointer to `Sid` with the
        // correct metadata (`sub_authority_count` elements in the trailing slice).
        let sub_authority_count = size_info.get_sub_authority_count();
        let mut ptr: NonNull<Sid> = unsafe {
            NonNull::new_unchecked(from_raw_parts_mut(
                mem_ptr as *mut (),
                sub_authority_count as usize,
            ))
        };
        // Initialize mandatory header field needed by later methods.
        unsafe {
            ptr.as_mut().sub_authority_count = sub_authority_count;
        }

        Self { sid: ptr, layout }
    }

    /// Retrieves the current user's SID from the process token (Windows only).
    ///
    /// # Errors
    /// Returns a `TokenError` when opening the token or querying it fails.
    ///
    /// # Examples
    /// ```no_run
    /// # #[cfg(windows)]
    /// # {
    /// # use win_security_identifier::SecurityIdentifier;
    /// let sid = SecurityIdentifier::get_current_user_sid().unwrap();
    /// println!("{}", sid);
    /// # }
    /// ```
    #[cfg(all(windows, feature = "std"))]
    pub fn get_current_user_sid() -> Result<Self, TokenError> {
        use std::os::windows::io::RawHandle;
        use windows_sys::Win32::{
            Foundation::GetLastError,
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        };
        unsafe {
            use core::ptr;

            let mut token_handle = MaybeUninit::<RawHandle>::uninit();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token_handle.as_mut_ptr()) == 0 {
                return Err(TokenError::OpenTokenFailed(GetLastError()));
            }
            let token_handle = token_handle.assume_init();

            let mut size = 0;
            if GetTokenInformation(token_handle, TokenUser, ptr::null_mut() as _, 0, &mut size) != 0
            {
                // Normally fails to report the required size.
                return Err(TokenError::GetTokenSizeFailed);
            }

            let mut buffer = vec![0u8; size as usize];

            if GetTokenInformation(
                token_handle,
                TokenUser,
                buffer.as_mut_ptr() as _,
                size,
                &mut size,
            ) == 0
            {
                return Err(TokenError::GetTokenInfoFailed(GetLastError()));
            }

            let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let sid = Sid::from_raw(token_user.User.Sid);
            Ok(sid.to_owned())
        }
    }

    /// Creates a `SecurityIdentifier` from a byte slice.
    ///
    /// This function attempts to parse a byte slice into a valid `SecurityIdentifier`.
    ///
    /// # Parameters
    /// - `bytes`: A type that can be referenced as a byte slice (`AsRef<[u8]>`).
    ///
    /// # Errors
    /// - [InvalidSidFormat] If the byte slice is not a valid SID format.
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
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, InvalidSidFormat> {
        let bytes = bytes.as_ref();
        bytes.try_into()
    }
    /// Returns a reference to this `ConstSid` as a dynamically-sized [`Sid`].
    ///
    /// This allows treating the fixed-size `ConstSid` as a regular `Sid`
    /// with a trailing slice of sub-authorities.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, SidIdentifierAuthority, Sid};
    /// let admin = SecurityIdentifier::try_new(
    ///     1,
    ///     SidIdentifierAuthority::NT_AUTHORITY,
    ///     [32, 544],
    /// ).unwrap();
    /// let sid: &Sid = admin.as_sid();
    /// assert_eq!(sid.to_string(), "S-1-5-32-544");
    /// ```
    pub const fn as_sid(&self) -> &Sid {
        unsafe { self.sid.as_ref() }
    }
}

impl TryFrom<&[u8]> for SecurityIdentifier {
    type Error = InvalidSidFormat;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let sid: &Sid = value.try_into()?;
        Ok(sid.to_owned())
    }
}

impl FromStr for SecurityIdentifier {
    type Err = InvalidSidFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let components = SidComponents::from_str(s)?;
        Ok(unsafe {
            Self::new_unchecked(
                components.revision,
                components.identifier_authority,
                components.sub_authority.as_slice(),
            )
        })
    }
}

impl ToOwned for Sid {
    type Owned = super::SecurityIdentifier;

    fn to_owned(&self) -> Self::Owned {
        unsafe {
            let binary = self.as_binary();
            let mut instance =
                Self::Owned::uninit(SidSizeInfo::from_full_size(binary.len()).unwrap_unchecked());
            instance.as_binary_mut().copy_from_slice(binary);
            instance
        }
    }
}

impl Borrow<Sid> for SecurityIdentifier {
    fn borrow(&self) -> &Sid {
        unsafe { self.sid.as_ref() }
    }
}

impl Deref for SecurityIdentifier {
    type Target = Sid;

    fn deref(&self) -> &Self::Target {
        unsafe { self.sid.as_ref() }
    }
}

impl DerefMut for SecurityIdentifier {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.sid.as_mut() }
    }
}

impl AsRef<Sid> for SecurityIdentifier {
    fn as_ref(&self) -> &Sid {
        unsafe { self.sid.as_ref() }
    }
}

impl AsMut<Sid> for SecurityIdentifier {
    fn as_mut(&mut self) -> &mut Sid {
        unsafe { self.sid.as_mut() }
    }
}

impl Drop for SecurityIdentifier {
    fn drop(&mut self) {
        unsafe { alloc::dealloc(self.sid.as_ptr() as *mut u8, self.layout) };
    }
}

impl Clone for SecurityIdentifier {
    fn clone(&self) -> Self {
        let mut sid =
            unsafe { Self::uninit(SidSizeInfo::from_count(self.sub_authority_count).unwrap()) };
        sid.clone_from(self);
        sid
    }

    fn clone_from(&mut self, source: &Self) {
        unsafe {
            self.as_binary_mut().copy_from_slice(source.as_binary());
        }
    }
}

impl Display for SecurityIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sid: &Sid = self.as_ref();
        Display::fmt(sid, f)
    }
}

impl Eq for SecurityIdentifier {}

impl PartialEq<Sid> for SecurityIdentifier {
    fn eq(&self, other: &Sid) -> bool {
        AsRef::<Sid>::as_ref(self) == other
    }
}

impl PartialEq<SecurityIdentifier> for Sid {
    fn eq(&self, other: &SecurityIdentifier) -> bool {
        self == other.as_ref()
    }
}

impl PartialEq for SecurityIdentifier {
    fn eq(&self, other: &Self) -> bool {
        AsRef::<Sid>::as_ref(self) == other.as_ref()
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::super::SecurityIdentifier;
    use super::super::Sid;
    use super::super::sid_identifier_authority::test::arb_identifier_authority;
    #[cfg(not(has_ptr_metadata))]
    use crate::polyfils_ptr::metadata;
    use proptest::prelude::*;

    use core::alloc::Layout;
    use core::hash::Hash;
    use core::hash::Hasher;
    use core::ops::Deref;
    #[cfg(has_ptr_metadata)]
    use core::ptr::metadata;

    pub fn arb_security_identifier() -> impl Strategy<Value = SecurityIdentifier> {
        (
            Just(1u8), // revision
            arb_identifier_authority(),
            proptest::collection::vec(any::<u32>(), 1..=15),
        )
            .prop_map(|(revision, identifier_authority, sub_authorities)| {
                let subs = &sub_authorities.as_slice();
                SecurityIdentifier::try_new(revision, identifier_authority, subs)
                    .expect("Failed to generate SecurityIdentifier")
            })
    }

    proptest! {
        #[test]
        fn test_sid_properties(security_identifier in arb_security_identifier()) {
            // Test access to inner Sid
            let sid: &Sid = security_identifier.as_ref();

            // Check length of sub_authorities
            assert_eq!(sid.get_sub_authorities().len(), sid.sub_authority_count as usize);

            // Display format: commence par S-1-
            let disp = format!("{sid}");
            prop_assert!(disp.starts_with("S-1-"), "Display doesn't start with S-1- : {}", disp);

            // ToOwned et Eq
            let owned_sid = sid.to_owned();
            let sid2 = owned_sid.deref();
            prop_assert_eq!(sid, sid2, "to_owned then deref should yield eq sids");

            // Hash
            use std::collections::hash_map::DefaultHasher;
            let mut h1 = DefaultHasher::new();
            sid.hash(&mut h1);
            let mut h2 = DefaultHasher::new();
            sid2.hash(&mut h2);
            prop_assert_eq!(h1.finish(), h2.finish(), "Hashes should match for equal SIDs");
        }

        #[test]
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

        #[cfg(has_layout_for_ptr)]
        #[test]
        fn test_layout_for_ptr(security_identifier in arb_security_identifier()){
            let raw_layout = unsafe{
                Layout::for_value_raw(security_identifier.sid.as_ptr())
            };
            prop_assert_eq!(security_identifier.layout, raw_layout);
        }

        #[test]
        fn test_sid_to_string_from_string(sid1 in arb_security_identifier()){
            let sid2: SecurityIdentifier = sid1.to_string().parse().unwrap();
            prop_assert_eq!(sid1, sid2);
        }
    }

    #[cfg(windows)]
    mod windows {
        use crate::SecurityIdentifier;

        use super::arb_security_identifier;
        use proptest::prelude::*;
        use windows_sys::Win32::Security::*;

        proptest! {
            #[test]
            fn test_init_sid_matches_rust_bytes(sid in arb_security_identifier()) {
                let subauth = sid.get_sub_authorities();
                let n = subauth.len() as u8;

                let required_size = unsafe { GetSidLengthRequired(n) } as usize;
                let mut buffer = vec![0u8; required_size];
                let sid_ptr = buffer.as_mut_ptr() as *mut SID;

                unsafe {
                    let ok = InitializeSid(
                        sid_ptr.cast(),
                        &sid.identifier_authority as *const _ as *const SID_IDENTIFIER_AUTHORITY,
                        n,
                    );
                    prop_assert!(ok != 0, "InitializeSid failed");

                    for (i, &sa) in subauth.iter().enumerate() {
                        let ptr = GetSidSubAuthority(sid_ptr.cast(), i as u32);
                        prop_assert!(!ptr.is_null(), "GetSidSubAuthority null at index {}", i);
                        *ptr = sa;
                    }

                    let win_len = GetLengthSid(sid_ptr.cast());
                    let win_bytes = std::slice::from_raw_parts(sid_ptr as *const u8, win_len as usize);

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
            let result = unsafe {
                if IsValidSid(sid.as_raw()) == 0 {
                    Some(windows_sys::Win32::Foundation::GetLastError())
                } else {
                    None
                }
            };
            assert!(result.is_none(), "SID is not valid: {result:?}");
        }
    }
}
