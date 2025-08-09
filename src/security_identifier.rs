use crate::Sid;
use crate::SidIdentifierAuthority;
#[cfg(not(has_ptr_metadata))]
use crate::polyfils_ptr::from_raw_parts_mut;
use crate::utils::sub_authority_size_guard;
#[cfg(has_ptr_metadata)]
use std::ptr::from_raw_parts_mut;
mod token_error;
use token_error::TokenError;
mod sid_size_info;
use arrayvec::ArrayVec;
pub(super) use sid_size_info::SidSizeInfo;
use std::alloc::{self, Layout};
use std::fmt::{self, Debug, Display};
use std::mem::MaybeUninit;
use std::ops::DerefMut;
use std::os::raw::c_void;
use std::str::FromStr;
use std::{borrow::Borrow, ops::Deref, ptr::NonNull};
use thiserror::Error;
#[cfg(windows)]
use windows_sys::Win32::Security::*;

pub struct SecurityIdentifier {
    sid: NonNull<Sid>,
    layout: Layout,
}

impl Debug for SecurityIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.deref(), f)
    }
}

impl SecurityIdentifier {
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
                let mut instance = Self::uninit(SidSizeInfo {
                    sub_authority_count,
                });
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

    pub unsafe fn new_unchecked<I: Into<SidIdentifierAuthority>, S: AsRef<[u32]>>(
        revision: u8,
        identifier_authority: I,
        sub_authority: S,
    ) -> Self {
        Self::try_new(revision, identifier_authority, sub_authority).unwrap()
    }

    unsafe fn uninit(size_info: SidSizeInfo) -> Self { unsafe {
        let layout = size_info.get_layout();
        let mem_ptr = alloc::alloc(layout);
        if mem_ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }
        let mut ptr: NonNull<Sid> = unsafe {
            NonNull::new_unchecked(from_raw_parts_mut(
                mem_ptr as *mut c_void,
                size_info.sub_authority_count as usize,
            ))
        };
        ptr.as_mut().sub_authority_count = size_info.sub_authority_count;
        Self {
            sid: ptr,
            layout,
        }
    }}

    #[cfg(windows)]
    pub fn get_current_user_sid<'a>() -> Result<SecurityIdentifier, TokenError> {
        use std::os::windows::io::RawHandle;
        use windows_sys::Win32::{
            Foundation::GetLastError,
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        };
        unsafe {
            use std::ptr;

            let mut token_handle = MaybeUninit::<RawHandle>::uninit();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token_handle.as_mut_ptr()) == 0 {
                return Err(TokenError::OpenTokenFailed(GetLastError()));
            }
            let token_handle = token_handle.assume_init();

            let mut size = 0;
            if GetTokenInformation(token_handle, TokenUser, ptr::null_mut() as _, 0, &mut size) != 0
            {
                // Normalement cette fonction échoue pour nous donner la taille requise
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
}
#[derive(Debug, Error)]
pub struct InvalidSidFormat;

impl Display for InvalidSidFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invalid format for Sid")
    }
}

impl FromStr for SecurityIdentifier {
    type Err = InvalidSidFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s_cmp = s.split("-");
        if !s_cmp
            .next()
            .map(|head| head.eq_ignore_ascii_case("s"))
            .unwrap_or(false)
        {
            return Err(InvalidSidFormat);
        }
        let revision = s_cmp
            .next()
            .ok_or(InvalidSidFormat)?
            .parse::<u8>()
            .map_err(|_| InvalidSidFormat)?;

        let authority = s_cmp
            .next()
            .ok_or(InvalidSidFormat)
            .and_then(|s| s.parse::<u64>().map_err(|_| InvalidSidFormat))
            .map(|value| {
                let bytes = value.to_be_bytes();
                SidIdentifierAuthority::from(<[u8; 6]>::try_from(&bytes[2..]).unwrap())
            })?;
        let mut sub_authorities = ArrayVec::<u32, 16>::new();
        for item in s_cmp {
            let item = item.parse::<u32>().map_err(|_| InvalidSidFormat)?;
            sub_authorities
                .try_push(item)
                .map_err(|_| InvalidSidFormat)?;
        }

        Ok(unsafe { Self::new_unchecked(revision, authority, sub_authorities.as_slice()) })
    }
}

impl ToOwned for Sid {
    type Owned = super::SecurityIdentifier;

    fn to_owned(&self) -> Self::Owned {
        unsafe {
            let binary = self.as_binary();
            let mut instance = Self::Owned::uninit(SidSizeInfo::from_full_size(binary.len()));
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
        let mut sid = unsafe {
            Self::uninit(SidSizeInfo {
                sub_authority_count: self.sub_authority_count,
            })
        };
        sid.clone_from(self);
        sid
    }

    fn clone_from(&mut self, source: &Self) {
        unsafe {
            self.as_binary_mut().copy_from_slice(source.as_binary());
        }
    }
}

impl Eq for SecurityIdentifier {}

impl PartialEq<Sid> for SecurityIdentifier {
    fn eq(&self, other: &Sid) -> bool {
        AsRef::<Sid>::as_ref(self) == other
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
    
    use std::hash::Hash;
    use std::hash::Hasher;
    use std::ops::Deref;
    #[cfg(has_ptr_metadata)]
    use std::ptr::metadata;

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
                        "Le SID Windows doit correspondre au SID Rust binaire"
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
