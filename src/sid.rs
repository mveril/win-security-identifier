
#[cfg(windows)]
mod windows;

use crate::SidIdentifierAuthority;

use crate::SidSizeInfo;

#[cfg(not(has_ptr_metadata))]
use crate::polyfils_ptr::from_raw_parts;
#[cfg(has_ptr_metadata)]
use std::ptr::from_raw_parts;
use std::{
    alloc::Layout,
    fmt::{self, Debug, Display},
    hash::Hash,
    mem::MaybeUninit,
    os::raw::c_void,
    ptr, slice,
};

#[repr(C)]
#[derive(Debug)]
pub struct Sid {
    pub revision: u8,
    pub(crate) sub_authority_count: u8,
    pub identifier_authority: SidIdentifierAuthority,
    pub sub_authority: [u32],
}

#[repr(C)]
pub(super) struct SidHead {
    pub revision: u8,
    pub sub_authority_count: u8,
    pub identifier_authority: SidIdentifierAuthority,
}

pub(super) const SID_HEAD_SIZE: usize = std::mem::size_of::<SidHead>();
pub(super) const SID_HEAD_ALIGN: usize = std::mem::align_of::<SidHead>();

impl Sid {
    pub unsafe fn as_binary(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const Self as *const u8,
                self.get_current_min_layoot().size(),
            )
        }
    }

    pub unsafe fn as_binary_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self as *const Self as *mut u8,
                self.get_current_min_layoot().size(),
            )
        }
    }

    pub fn get_sub_authorities(&self) -> &[u32] {
        unsafe {
            slice::from_raw_parts(
                self.sub_authority.as_ptr(),
                self.sub_authority_count as usize,
            )
        }
    }

    pub(super) fn get_current_min_layoot(&self) -> Layout {
        let size_info = SidSizeInfo {
            sub_authority_count: self.sub_authority_count,
        };
        size_info.get_layout()
    }
}

impl Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Write the revision (should always be 1 in modern SIDs)
        write!(f, "S-{}", self.revision)?;

        // Identifier Authority: print as decimal if fits in u32, else as hex
        let mut be_bytes = [0u8; 8];
        be_bytes[2..].copy_from_slice(&self.identifier_authority.value.as_slice());
        let id_auth_value = u64::from_be_bytes(be_bytes);
        if id_auth_value <= 0xFFFFFFFF {
            write!(f, "-{}", id_auth_value)?;
        } else {
            write!(f, "-0x{:X}", id_auth_value)?;
        }

        // SubAuthorities
        for &sub_auth in self.get_sub_authorities() {
            write!(f, "-{}", sub_auth)?;
        }
        Ok(())
    }
}

impl PartialEq for Sid {
    fn eq(&self, other: &Self) -> bool {
        unsafe { self.as_binary() == other.as_binary() }
    }
}

impl Eq for Sid {}
impl Hash for Sid {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.revision.hash(state);
        self.sub_authority_count.hash(state);
        self.identifier_authority.hash(state);
        Hash::hash_slice(&self.get_sub_authorities(), state);
    }
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;
    use std::ops::Deref;

    use crate::{SecurityIdentifier, arb_security_identifier};

    use super::super::arb_identifier_authority;
    use super::*;
    use proptest::prelude::*;
    use widestring::WideCString;
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

            // Si binaire identique, Eq doit l'être aussi (même instance)
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
        use std::ops::Deref;

        use crate::{SecurityIdentifier, arb_security_identifier};

        use super::super::*;
        use proptest::prelude::*;
        use widestring::{WideCStr, WideCString, widecstr};
        use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
        use windows_sys::Win32::Security::Authorization::*;
        use windows_sys::Win32::Security::*;
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
