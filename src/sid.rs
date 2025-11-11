//! Low-level, zero-copy representation of a Windows Security Identifier (SID).
//!
//! This module exposes a `repr(C)` view (`Sid`) with a dynamically-sized
//! trailing slice of sub-authorities, and a fixed-size header (`SidHead`).
//! It provides read-only accessors and helpers to get the current minimal
//! binary layout required for the instance.
//!
//! **Important:** `Sid` is layout-sensitive and intended to be allocated and
//! owned by higher-level types (e.g., `SecurityIdentifier`). Direct mutation
//! or construction must respect Windows SID invariants.

#[cfg(all(windows, feature = "std"))]
mod windows;
#[cfg(all(windows, feature = "std"))]
pub use windows::sid_lookup;

use crate::InvalidSidFormat;
use crate::utils::validate_sid_bytes_unaligned;

pub use parsing::MAX_SUBAUTHORITY_COUNT;
pub use parsing::MIN_SUBAUTHORITY_COUNT;

#[cfg(not(has_ptr_metadata))]
use crate::polyfills_ptr::from_raw_parts;
#[cfg(has_ptr_metadata)]
use core::ptr::from_raw_parts;

use crate::{SidIdentifierAuthority, SidSizeInfo};

use core::{
    alloc::Layout,
    fmt::{self, Debug, Display},
    hash::Hash,
    slice,
};

/// C-compatible, dynamically-sized Windows Security Identifier.
///
/// This is a **DST** (`[u32]` tail) representing:
/// - `revision`: SID revision (commonly `1`),
/// - `sub_authority_count`: number of [u32] elements in the trailing slice,
/// - `identifier_authority`: 6-byte identifier authority,
/// - `sub_authority`: trailing slice of [u32] elements (length = `sub_authority_count`).
///
/// # Layout
/// The layout matches the Windows SID memory representation:
/// a fixed header followed by `sub_authority_count` 32-bit values.
///
/// # Invariants
/// - `sub_authority` length equals `sub_authority_count`.
/// - `sub_authority_count` ∈ 1..=15 for valid Windows SIDs.
/// - The allocation size must be consistent with `SidSizeInfo`.
///
/// Instances are typically created and owned by a safe wrapper (e.g. `SecurityIdentifier`).
#[repr(C)]
#[derive(Debug)]
pub struct Sid {
    /// The SID revision value, generally 1.
    pub revision: u8,
    pub(crate) sub_authority_count: u8,
    /// The SID identifier authority value.
    pub identifier_authority: SidIdentifierAuthority,
    /// The SID sub-authority values.
    pub sub_authority: [u32],
}

/// Fixed-size header of a SID (no trailing sub-authorities).
///
/// Useful when computing minimal layouts and when manipulating metadata
/// independently of the dynamic tail.
#[repr(C)]
pub struct SidHead {
    pub revision: u8,
    pub sub_authority_count: u8,
    pub identifier_authority: SidIdentifierAuthority,
}
#[allow(dead_code)]
pub const SID_HEAD_SIZE: usize = core::mem::size_of::<SidHead>();

impl Sid {
    /// Returns a `&[u8]` view over the **currently valid** minimal binary representation of this SID.
    ///
    /// The slice covers the header and the exact number of sub-authorities currently set
    /// (based on `sub_authority_count`).
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{ConstSid, well_known, Sid, SidIdentifierAuthority};
    /// let const_sid = well_known::BUILTIN_ADMINISTRATORS;
    /// let sid: &Sid = const_sid.as_ref();
    /// unsafe {
    ///     let bytes = sid.as_binary();
    ///     assert_eq!(bytes, [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]);
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub const fn as_binary(&self) -> &[u8] {
        // Safety:
        // - The instance must be fully initialized and backed by a valid allocation large enough
        //   for the computed layout (see `get_current_min_layout`).
        // - The lifetime of the returned slice is tied to `&self`.
        unsafe {
            let layout = self.get_current_min_layout();
            let len = layout.size();
            slice::from_raw_parts(core::ptr::from_ref(self).cast::<u8>(), len)
        }
    }

    const unsafe fn from_raw_internal<'a>(raw: *const ()) -> &'a Self {
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "single unsafe block for clarity"
        )]
        // Safety: precondition defined in the method doc.
        unsafe {
            // Read sub_authority_count by forging a fat pointer with metadata=0 first.
            let metadata = {
                let ptr: *const Self = from_raw_parts(raw, 0);
                (*ptr).sub_authority_count
            };
            &*from_raw_parts(raw.cast::<()>(), metadata as usize)
        }
    }

    /// Returns a `&mut [u8]` view over the **currently valid** minimal binary representation.
    ///
    /// This can be used for low-level, in-place updates when you know exactly what you are doing.
    ///
    /// # Safety
    /// - Same preconditions as `as_binary`.
    /// - Mutating the buffer must preserve SID invariants (e.g., do not desynchronize
    ///   `sub_authority_count` and the tail length).
    #[allow(dead_code)]
    pub(crate) const unsafe fn as_binary_mut(&mut self) -> &mut [u8] {
        // Safety: Precondition definied in the method doc.
        unsafe {
            slice::from_raw_parts_mut(
                core::ptr::from_ref(self).cast_mut().cast::<u8>(),
                self.get_current_min_layout().size(),
            )
        }
    }

    /// Returns the slice of sub-authorities (`[u32]`) with length `sub_authority_count`.
    ///
    /// # Notes
    /// This is a read-only view. Mutation should be performed through higher-level safe APIs
    /// that maintain invariants.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{Sid, ConstSid, SidIdentifierAuthority};
    /// let const_sid = ConstSid::<1>::new(1, SidIdentifierAuthority::NT_AUTHORITY, [1]);
    /// let sid = const_sid.as_sid();
    /// let subs = sid.get_sub_authorities();
    /// assert_eq!(subs, &[1]);
    /// ```
    #[must_use]
    #[inline]
    pub const fn get_sub_authorities(&self) -> &[u32] {
        // Safety: self is valid and fully initialized.
        unsafe {
            slice::from_raw_parts(
                self.sub_authority.as_ptr(),
                self.sub_authority_count as usize,
            )
        }
    }

    /// Computes the minimal `Layout` (size + align) needed for **this** instance
    /// given its current `sub_authority_count`.
    ///
    /// This is typically used to:
    /// - validate backing allocations,
    /// - compute binary slice lengths,
    /// - interoperate with low-level allocators.
    #[must_use]
    #[inline]
    pub const fn get_current_min_layout(&self) -> Layout {
        if let Some(info) = SidSizeInfo::from_count(self.sub_authority_count) {
            info.get_layout()
        } else {
            unreachable!()
        }
    }

    /// Attempts to construct a `&Sid` from a raw byte slice.
    /// Returns an error if the byte slice is not a valid SID.
    /// # Errors
    /// Invalid Sid format if the buffer is not an [Sid]
    /// # Safety
    /// Alignment is not checked the alignment need to be `align_of!(u32)`
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{Sid, SidIdentifierAuthority, ConstSid};
    /// # let const_sid = ConstSid::<1>::new(1,  SidIdentifierAuthority::NT_AUTHORITY, [20u32]);
    /// # let bytes = const_sid.as_bytes();
    /// // Build a SID S-1-5-32-544 (Builtin\Administrators) from parts and :
    /// let sid = unsafe{ Sid::from_bytes(bytes) }.expect("valid SID parts");
    /// assert_eq!(sid.revision, 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.get_sub_authorities(), [20u32]);
    #[inline]
    pub const unsafe fn from_bytes(value: &[u8]) -> Result<&Self, InvalidSidFormat> {
        if let Err(err) = validate_sid_bytes_unaligned(value) {
            return Err(err);
        }
        Ok(
            // Safety: value length has been validated against the expected layout size.
            unsafe { Self::from_raw_internal(value.as_ptr().cast()) },
        )
    }
}

// --- Standard trait impls intentionally left undocumented (per your request) ---

impl Display for Sid {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Write the revision (should always be 1 in modern SIDs)
        write!(f, "S-{}", self.revision)?;

        // Identifier Authority: print as decimal if fits in u32, else as hex
        let mut be_bytes = [0u8; 8];
        be_bytes[2..].copy_from_slice(self.identifier_authority.value.as_slice());
        let id_auth_value = u64::from_be_bytes(be_bytes);
        if id_auth_value <= 0xFFFF_FFFF {
            write!(f, "-{id_auth_value}")?;
        } else {
            write!(f, "-0x{id_auth_value:X}")?;
        }

        // SubAuthorities
        for &sub_auth in self.get_sub_authorities() {
            write!(f, "-{sub_auth}")?;
        }
        Ok(())
    }
}

impl PartialEq for Sid {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_binary() == other.as_binary()
    }
}

impl Eq for Sid {}
impl Hash for Sid {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.revision.hash(state);
        self.sub_authority_count.hash(state);
        self.identifier_authority.hash(state);
        Hash::hash_slice(self.get_sub_authorities(), state);
    }
}

#[allow(clippy::unwrap_used, reason = "Unwrap is not an issue in test")]
#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use crate::{SecurityIdentifier, arb_security_identifier};
    use core::hash::Hasher;
    use core::ops::Deref;

    use super::*;
    use proptest::prelude::*;

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn sid_display_round_trip(sid in arb_security_identifier()) {
            let display = sid.deref().to_string();
            prop_assert!(display.starts_with("S-1-"), "Display does not start with S-1-: {}", display);

            let dash_count = display.matches('-').count();
            let expected = (sid.sub_authority_count as usize) + 2;
            prop_assert_eq!(dash_count, expected, "Dash count {} vs sub_authority_count {}", dash_count, expected);
            prop_assert_eq!(display.parse::<SecurityIdentifier>().unwrap(), sid);
        }
        #[test]
        fn sid_hash_and_eq(sid1 in arb_security_identifier(), sid2 in arb_security_identifier()) {
            use std::collections::hash_map::DefaultHasher;
            // Reflexivity
            prop_assert_eq!(&*sid1, &*sid1);

            // If binary is identical, Eq must be true too (same logical SID)
            let sid2_clone = sid1.clone();
            prop_assert_eq!(&sid1, &sid2_clone);
            let mut hasher1 = DefaultHasher::new();
            sid1.hash(&mut hasher1);
            let mut hasher2 = DefaultHasher::new();
            sid2_clone.hash(&mut hasher2);
            prop_assert_eq!(hasher1.finish(), hasher2.finish());
            if sid1 != sid2 {
                let mut hasher2 = DefaultHasher::new();
                sid2.hash(&mut hasher2);
                prop_assert!(hasher1.finish() != hasher2.finish() || sid1 == sid2, "Hash collision with different sids");
            }
        }

        #[test]
        fn sid_sub_authorities_len(sid in arb_security_identifier()) {
            let subs = sid.get_sub_authorities();
            prop_assert_eq!(subs.len(), sid.sub_authority_count as usize);
        }
    }

    #[cfg(windows)]
    mod windows {
        use super::super::*;
        #[cfg(feature = "alloc")]
        use crate::arb_security_identifier;
        use core::ffi::c_void;
        use core::mem::MaybeUninit;
        use proptest::prelude::*;
        use widestring::{WideCStr, WideCString};
        use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
        use windows_sys::Win32::Security::Authorization::*;

        #[cfg(feature = "std")]
        proptest! {
        #[test]
        fn test_to_string_windows_parsable(r_sid in arb_security_identifier()) {
            let sid_str = r_sid.to_string();

            // SAFETY: Building a wide string from our UTF-8 Rust string.
            // `from_str_unchecked` skips interior NUL checks by design; we rely on `to_string()` not producing NULs.
            let sid_wstr = unsafe{ WideCString::from_str_unchecked(sid_str.as_str())};

            // Will be written by the WinAPI on success. Uninitialized for now.
            let mut sid_uninit: MaybeUninit<*mut c_void> = MaybeUninit::uninit();

            // Call the WinAPI and capture a possible error code.
            let error = {
                // SAFETY:
                // - `sid_wstr.as_ptr()` yields a valid pointer to a NUL-terminated UTF-16 buffer
                //   whose lifetime extends through this call.
                // - `sid_uninit.as_mut_ptr()` is a valid out-parameter of type `*mut *mut c_void`.
                // - On success (nonzero return), the API initializes it with a non-null pointer
                //   to a SID allocated by the system (LocalAlloc).
                // - On failure (return == 0), the out-parameter must be considered uninitialized
                //   and MUST NOT be freed.
                let ok = unsafe { ConvertStringSidToSidW(sid_wstr.as_ptr(), sid_uninit.as_mut_ptr()) };
                // SAFETY: `GetLastError` reads the thread-local last-error; calling immediately after
                // the failing WinAPI is the canonical usage.
                (ok == 0).then_some(unsafe { GetLastError() })};

            // If the call failed, the test exits here; we never touch the uninitialized pointer.
            prop_assert_eq!(error, None);

            // From here, the out-parameter is initialized by the OS. It is safe to assume_init().
            // SAFETY:
            // - We just asserted success (`error == None`), so `sid_uninit` has been written by
            //   ConvertStringSidToSidW and now holds a valid, non-null pointer to a system-allocated SID.
            let sid = unsafe {
                sid_uninit.assume_init()
            };
            prop_assert!(!sid.is_null());

            // SAFETY: of using the raw pointer is delegated to `Sid::from_raw`'s contract (constructor function):
            // it must not outlive the underlying allocation and must not assume ownership.
            let sid_ref = unsafe{ Sid::from_raw(sid)};

            prop_assert_eq!(sid_ref.to_string(), sid_str);
            prop_assert_eq!(sid_ref, &*r_sid);
            // SAFETY:
            // - The SID pointer was allocated by the system (LocalAlloc via ConvertStringSidToSidW).
            // - We are freeing it exactly once, and we have no remaining aliases used after this call.
            unsafe {
                LocalFree(sid.cast::<c_void>());
            }
        }


                #[test]
                fn test_to_string_same(sid in arb_security_identifier()) {
                    let sid_str = sid.to_string();

                    let mut sid_wstr_uninit = MaybeUninit::<*mut u16>::uninit();

                    let error = {
                        // SAFETY:
                        // - `sid.as_raw()` must yield a non-null pointer to a valid SID for the duration of the call.
                        //   This is guaranteed by the property of `sid` and its lifetime within this test.
                        // - `sid_wstr_uninit.as_mut_ptr()` is a valid out-parameter of type `*mut *mut u16`.
                        //   On success (nonzero return), the API initializes it with a non-null pointer to a
                        //   NUL-terminated UTF-16 string allocated by LocalAlloc.
                        // - On failure (return == 0), the out-parameter must be considered uninitialized and MUST NOT be freed.
                        let ok = unsafe { ConvertSidToStringSidW(sid.as_raw(), sid_wstr_uninit.as_mut_ptr()) };
                        (ok == 0).then_some(
                            // SAFETY: Get last error is always safe
                            unsafe { GetLastError() })
                    };

                    prop_assert_eq!(error, None);

                    // SAFETY:
                    // - We just asserted success (`error == None`), so `sid_wstr_uninit` has been written by
                    //   ConvertSidToStringSidW and now holds a valid pointer.
                    let sid_wstr_ptr = unsafe {
                        sid_wstr_uninit.assume_init()
                    };
                    prop_assert!(!sid_wstr_ptr.is_null());

                    {
                        // SAFETY:
                        // - On success, the API guarantees `sid_wstr_ptr` points to a valid, NUL-terminated UTF-16 buffer.
                        // - `WideCStr::from_ptr_str` reads until the first NUL and does not take ownership.
                        let sid_wstr = unsafe { WideCStr::from_ptr_str(sid_wstr_ptr) };
                        prop_assert_eq!(sid_str, sid_wstr.to_string_lossy());
                    }

                    // Release the system-allocated buffer exactly once.
                    // SAFETY:
                    // - The buffer was allocated by the system (LocalAlloc via ConvertSidToStringSidW).
                    // - We are freeing it exactly once, and we have no remaining aliases used after this call.
                    unsafe {
                        LocalFree(sid_wstr_ptr.cast::<c_void>());
                    }
                }

        }
    }
}
