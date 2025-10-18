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
use core::ops::DerefMut;
use core::str::FromStr;
use core::{ops::Deref, ptr::NonNull};
#[cfg(feature = "std")]
use std::{alloc, borrow::Borrow, borrow::ToOwned};
#[cfg(all(windows, feature = "std"))]
pub use token_error::TokenError;

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
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&**self, f)
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
    #[inline]
    pub fn try_new<I: Into<SidIdentifierAuthority>, S: AsRef<[u32]>>(
        revision: u8,
        identifier_authority: I,
        sub_authority: S,
    ) -> Option<Self> {
        let sub_authority = sub_authority.as_ref();
        // SAFETY: sub_authority_count is correctly validated by guard.
        sub_authority_size_guard(sub_authority.len()).then_some(unsafe {
            Self::new_unchecked(revision, identifier_authority, sub_authority)
        })
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
    #[must_use]
    #[inline]
    pub unsafe fn new_unchecked<I: Into<SidIdentifierAuthority>, S: AsRef<[u32]>>(
        revision: u8,
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
        let mut instance = unsafe { Self::uninit(size_info) };
        // Safety: sid is valid here to be fill.
        let sid_ref = unsafe { instance.sid.as_mut() };
        sid_ref.revision = revision;
        sid_ref.sub_authority_count = sub_authority_count;
        sid_ref.identifier_authority = identifier_authority;
        sid_ref.sub_authority.copy_from_slice(sub_authority);
        instance
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
        // SAFETY: layout is valid and non-zero sized.
        let mem_ptr = unsafe { alloc::alloc(layout) };
        if mem_ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }
        let sub_authority_count = size_info.get_sub_authority_count();
        // SAFETY: `from_raw_parts_mut` builds a fat pointer to `Sid` with the
        // correct metadata (`sub_authority_count` elements in the trailing slice).
        
        let mut ptr: NonNull<Sid> = unsafe {
            NonNull::new_unchecked(from_raw_parts_mut(
                mem_ptr.cast::<()>(),
                sub_authority_count as usize,
            ))
        };
        // Initialize mandatory header field needed by later methods.
        // SAFETY: `ptr` was initialized just above.
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
    #[expect(
        clippy::missing_inline_in_public_items,
        reason = "Cannot be inlined because it's a big method"
    )]
    pub fn get_current_user_sid() -> Result<Self, TokenError> {
        use core::mem::MaybeUninit;
        use core::ptr;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
        use windows_sys::Win32::{
            Foundation::GetLastError,
            Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser},
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        };

        // --- Open the process token ------------------------------------------------
        let mut raw_handle_mu: MaybeUninit<RawHandle> = MaybeUninit::uninit();

        // SAFETY: GetCurrentProcess is side-effect free and can be called unconditionally.
        let process_handle = unsafe { GetCurrentProcess() };
        // SAFETY: FFI call; pointers are valid. We check the return value immediately.
        let open_ok =
            unsafe { OpenProcessToken(process_handle, TOKEN_QUERY, raw_handle_mu.as_mut_ptr()) };

        if open_ok == 0 {
            // SAFETY: GetLastError is side-effect free and can be called unconditionally.
            let err = unsafe { GetLastError() };
            return Err(TokenError::OpenTokenFailed(err));
        }

        // SAFETY: OpenProcessToken reported success; the handle is initialized.
        let raw_handle: RawHandle = unsafe { raw_handle_mu.assume_init() };

        // SAFETY: `raw_handle` is a valid owned handle obtained from the OS.
        let token_handle: OwnedHandle = unsafe { OwnedHandle::from_raw_handle(raw_handle) };

        // --- First GetTokenInformation to obtain required size ---------------------
        let mut size: u32 = 0;
        // SAFETY: Standard size-query pattern with null buffer and 0 length.
        let first_ok = unsafe {
            GetTokenInformation(
                token_handle.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &raw mut size,
            )
        };

        if first_ok != 0 {
            // Unexpected success: should fail to report size.
            return Err(TokenError::GetTokenSizeFailed);
        }

        // --- Allocate buffer with reported size ------------------------------------
        let mut buffer = vec![0u8; size as usize];

        // SAFETY: Buffer pointer/length are consistent with allocation; size was set by the API.
        let second_ok = unsafe {
            GetTokenInformation(
                token_handle.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &raw mut size,
            )
        };

        if second_ok == 0 {
            // SAFETY: GetLastError can be called immediately after a failing FFI call.
            let err = unsafe { GetLastError() };
            return Err(TokenError::GetTokenInfoFailed(err));
        }
        #[expect(
            clippy::cast_ptr_alignment,
            reason = "read_unaligned handles unaligned access"
        )]
        let token_user_ptr = buffer.as_ptr().cast::<TOKEN_USER>();
        // SAFETY: TOKEN_USER is a plain data struct and can be read from a byte buffer.
        let sid_ptr = unsafe { ptr::addr_of!((*token_user_ptr).User.Sid) };
        // SAFETY: TOKEN_USER contains a PSID which is a pointer to a valid SID.
        let raw_sid = unsafe { ptr::read_unaligned(sid_ptr) };
        // SAFETY: get the user Sid from the raw pointer structure.
        let sid = unsafe { Sid::from_raw(raw_sid) };
        Ok(sid.to_owned())
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
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, InvalidSidFormat> {
        let bytes = bytes.as_ref();
        bytes.try_into()
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
    ///     1,
    ///     SidIdentifierAuthority::NT_AUTHORITY,
    ///     [32, 544],
    /// ).unwrap();
    /// let sid: &Sid = admin.as_sid();
    /// assert_eq!(sid.to_string(), "S-1-5-32-544");
    /// ```
    #[inline]
    #[must_use]
    pub const fn as_sid(&self) -> &Sid {
        // SAFETY: self.sid is guaranteed to be valid.
        unsafe { self.sid.as_ref() }
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
    ///     1,
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
    pub const fn as_sid_mut(&mut self) -> &mut Sid {
        // SAFETY: self.sid is guaranteed to be valid.
        unsafe { self.sid.as_mut() }
    }
}

impl TryFrom<&[u8]> for SecurityIdentifier {
    type Error = InvalidSidFormat;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let sid: &Sid = value.try_into()?;
        Ok(sid.to_owned())
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
                    components.revision,
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
        let binary = self.as_binary();
        // Safety: sub_authority_count is known to be valid because `self` is valid.
        let size_info =
            unsafe { SidSizeInfo::from_count(self.sub_authority_count).unwrap_unchecked() };
        // Safety: The uninit SID is properly initialized by copying from `self` after.
        let mut instance = unsafe { Self::Owned::uninit(size_info) };
        // Safety: We copy all the bytes from a valid SID of the same size.
        unsafe {
            instance.as_binary_mut().copy_from_slice(binary);
        }
        instance
    }
}

impl Borrow<Sid> for SecurityIdentifier {
    #[inline]
    fn borrow(&self) -> &Sid {
        // SAFETY: self.sid is guaranteed to be valid.
        unsafe { self.sid.as_ref() }
    }
}

impl Deref for SecurityIdentifier {
    type Target = Sid;
    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: self.sid is guaranteed to be valid.
        unsafe { self.sid.as_ref() }
    }
}

impl DerefMut for SecurityIdentifier {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: self.sid is guaranteed to be valid.
        unsafe { self.sid.as_mut() }
    }
}

impl AsRef<Sid> for SecurityIdentifier {
    #[inline]
    fn as_ref(&self) -> &Sid {
        // Safety: self.sid is guaranteed to be valid.
        unsafe { self.sid.as_ref() }
    }
}

impl AsMut<Sid> for SecurityIdentifier {
    #[inline]
    fn as_mut(&mut self) -> &mut Sid {
        // SAFETY: self.sid is guaranteed to be valid.
        unsafe { self.sid.as_mut() }
    }
}

impl Drop for SecurityIdentifier {
    #[inline]
    fn drop(&mut self) {
        // Safety: The layout is valid and the pointer is properly aligned.
        unsafe { alloc::dealloc(self.sid.as_ptr().cast::<u8>(), self.layout) };
    }
}

impl Clone for SecurityIdentifier {
    #[inline]
    fn clone(&self) -> Self {
        // Safety: both `self` and the returned instance are valid SIDs with the same layout.
        let size_info =
            unsafe { SidSizeInfo::from_count(self.sub_authority_count).unwrap_unchecked() };
        // Safety: The uninit SID is properly initialized by `clone_from`.
        let mut sid = unsafe { Self::uninit(size_info) };
        sid.clone_from(self);
        sid
    }
    #[inline]
    fn clone_from(&mut self, source: &Self) {
        // Safety: both `self` and `source` are valid SIDs with the same layout.
        unsafe {
            self.as_binary_mut().copy_from_slice(source.as_binary());
        }
    }
}

impl Display for SecurityIdentifier {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sid: &Sid = self.as_ref();
        Display::fmt(sid, f)
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

impl PartialEq for SecurityIdentifier {
    #[inline]
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
