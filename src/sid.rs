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

use crate::InvalidSidFormat;

pub(crate) const MIN_SUBAUTHORITY_COUNT: u8 = 1;
pub(crate) const MAX_SUBAUTHORITY_COUNT: u8 = 15;

#[cfg(not(has_ptr_metadata))]
use crate::polyfils_ptr::from_raw_parts;
#[cfg(has_ptr_metadata)]
use std::ptr::from_raw_parts;

use crate::{SidIdentifierAuthority, SidSizeInfo, utils::sub_authority_size_guard};

use core::{
    alloc::Layout,
    fmt::{self, Debug, Display},
    hash::Hash,
    mem::offset_of,
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
pub(crate) struct SidHead {
    pub revision: u8,
    pub sub_authority_count: u8,
    pub identifier_authority: SidIdentifierAuthority,
}

/// Size (in bytes) of the fixed `SidHead` header.
pub(crate) const SID_HEAD_SIZE: usize = core::mem::size_of::<SidHead>();
/// Alignment (in bytes) of the fixed `SidHead` header.
#[allow(dead_code)]
pub(crate) const SID_HEAD_ALIGN: usize = core::mem::align_of::<SidHead>();

impl Sid {
    /// Returns a `&[u8]` view over the **currently valid** minimal binary representation of this SID.
    ///
    /// The slice covers the header and the exact number of sub-authorities currently set
    /// (based on `sub_authority_count`).
    ///
    /// # Safety
    /// - The instance must be fully initialized and backed by a valid allocation large enough
    ///   for the computed layout (see `get_current_min_layoot`).
    /// - The lifetime of the returned slice is tied to `&self`.
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
    pub const fn as_binary(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const Self as *const u8,
                self.get_current_min_layout().size(),
            )
        }
    }

    const unsafe fn from_raw_internal<'a>(raw: *const ()) -> &'a Self {
        unsafe {
            // Read sub_authority_count by forging a fat pointer with metadata=0 first.
            let metadata = {
                let ptr: *const Sid = from_raw_parts(raw, 0);
                (*ptr).sub_authority_count
            };
            &*from_raw_parts(raw as *mut () as *const (), metadata as usize)
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
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn as_binary_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self as *const Self as *mut u8,
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
    pub const fn get_sub_authorities(&self) -> &[u32] {
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
    pub const fn get_current_min_layout(&self) -> Layout {
        match SidSizeInfo::from_count(self.sub_authority_count) {
            Some(info) => info.get_layout(),
            None => unreachable!(),
        }
    }
}

// --- Standard trait impls intentionally left undocumented (per your request) ---

impl Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Write the revision (should always be 1 in modern SIDs)
        write!(f, "S-{}", self.revision)?;

        // Identifier Authority: print as decimal if fits in u32, else as hex
        let mut be_bytes = [0u8; 8];
        be_bytes[2..].copy_from_slice(self.identifier_authority.value.as_slice());
        let id_auth_value = u64::from_be_bytes(be_bytes);
        if id_auth_value <= 0xFFFFFFFF {
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
    fn eq(&self, other: &Self) -> bool {
        self.as_binary() == other.as_binary()
    }
}

impl Eq for Sid {}
impl Hash for Sid {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.revision.hash(state);
        self.sub_authority_count.hash(state);
        self.identifier_authority.hash(state);
        Hash::hash_slice(self.get_sub_authorities(), state);
    }
}

impl TryFrom<&[u8]> for &Sid {
    type Error = InvalidSidFormat;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let min_size = match SidSizeInfo::from_count(1) {
            Some(info) => info.get_layout().size(),
            None => unreachable!(),
        };
        if value.len() < min_size {
            return Err(InvalidSidFormat);
        }

        let count_offset = offset_of!(Sid, sub_authority_count);
        let count = value[count_offset];

        if !sub_authority_size_guard(count as usize) {
            return Err(InvalidSidFormat);
        }

        let size = match SidSizeInfo::from_count(count) {
            Some(info) => info.get_layout().size(),
            None => unreachable!(),
        };
        if value.len() != size {
            return Err(InvalidSidFormat);
        }
        Ok(unsafe { Sid::from_raw_internal(value.as_ptr() as *const ()) })
    }
}
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
            // Reflexivity
            prop_assert_eq!(sid1.deref(), sid1.deref());

            // If binary is identical, Eq must be true too (same logical SID)
            let sid2_clone = sid1.clone();
            prop_assert_eq!(&sid1, &sid2_clone);
            use std::collections::hash_map::DefaultHasher;
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
        use core::ops::Deref;

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
                unsafe {
                    let sid_str = r_sid.to_string();
                    let sid_wstr = WideCString::from_str_unchecked(sid_str.as_str());
                    let mut sid_uninit: MaybeUninit<*mut c_void> = MaybeUninit::uninit();
                    let error =
                        if ConvertStringSidToSidW(sid_wstr.as_ptr(), sid_uninit.as_mut_ptr()) == 0 {
                            Some(GetLastError())
                        } else {
                            None
                        };
                    prop_assert_eq!(error, None);
                    let sid = sid_uninit.assume_init();
                    prop_assert!(!sid.is_null());
                    let sid_ref = Sid::from_raw(sid);
                    prop_assert_eq!(
                        sid_ref.to_string(),
                        sid_str
                    );
                    prop_assert_eq!(sid_ref, r_sid.deref());
                    LocalFree(sid as *mut c_void);
                }
            }

            #[test]
            fn test_to_string_same(sid in arb_security_identifier()) {
                unsafe {
                    let sid_str = sid.to_string();
                    let mut sid_wstr_uninit = MaybeUninit::<*mut u16>::uninit();
                    let error =
                        if ConvertSidToStringSidW(sid.as_raw(), sid_wstr_uninit.as_mut_ptr()) == 0 {
                            Some(GetLastError())
                        } else {
                            None
                        };
                    prop_assert_eq!(error, None);
                    let sid_wstr_ptr = sid_wstr_uninit.assume_init();
                    prop_assert!(!sid_wstr_ptr.is_null());
                    {
                        let sid_wstr = WideCStr::from_ptr_str(sid_wstr_ptr);
                        prop_assert_eq!(sid_str, sid_wstr.to_string_lossy());
                    }
                    LocalFree(sid_wstr_ptr as *mut c_void);
                }
            }
        }
    }
}
