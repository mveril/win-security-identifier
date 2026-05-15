use crate::SecurityIdentifier;

use super::Error;
use super::SidType;
use super::domain_and_name::DomainAndName;
use core::ptr::{null, null_mut};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use smallvec::SmallVec;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStringExt;
use widestring::U16CString;
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::{
    Foundation::GetLastError,
    Security::LookupAccountNameW,
};

type LookupBuffer = SmallVec<[u16; 256]>;
type SidBuffer = SmallVec<[u8; 128]>;

/// Result of a Windows account-name lookup.
pub struct AccountLookup {
    /// The SID associated with the account name.
    pub sid: SecurityIdentifier,
    /// The canonical domain and account name returned by Windows.
    pub domain_name: DomainAndName,
    /// The raw SID type value.
    pub sid_type_raw: i32,
}

impl AccountLookup {
    /// Get the SID type as an enum.
    /// # Errors
    /// Return a [`TryFromPrimitiveError<SidType>`] error if the raw SID type value is unknown.
    #[inline]
    pub fn sid_type(&self) -> Result<SidType, TryFromPrimitiveError<SidType>> {
        SidType::try_from_primitive(self.sid_type_raw)
    }
}

struct AccountLookupOperation<'a> {
    account_name: &'a U16CString,
    machine_name: Option<&'a U16CString>,
    sid_len: u32,
    domain_len: u32,
    sid_type_raw: i32,
}

impl<'a> AccountLookupOperation<'a> {
    fn new(account_name: &'a U16CString, machine_name: Option<&'a U16CString>) -> Option<Self> {
        let mut sid_len = 0u32;
        let mut domain_len = 0u32;
        let mut sid_type_raw = 0i32;
        let machine_name_ptr = machine_name.map_or(null(), |s| s.as_ptr());

        // SAFETY: All pointers are either null for the size-query call or valid NUL-terminated UTF-16 strings.
        let result = unsafe {
            LookupAccountNameW(
                machine_name_ptr,
                account_name.as_ptr(),
                null_mut(),
                &raw mut sid_len,
                null_mut(),
                &raw mut domain_len,
                &raw mut sid_type_raw,
            )
        };
        if result != 0 {
            return None;
        }
        // SAFETY: `GetLastError` is safe to call immediately after a failing Win32 call.
        let err = Error::from(unsafe { GetLastError() });
        if err != Error::Other(ERROR_INSUFFICIENT_BUFFER) {
            return None;
        }

        Some(Self {
            account_name,
            machine_name,
            sid_len,
            domain_len,
            sid_type_raw,
        })
    }

    fn process(mut self) -> Result<AccountLookup, Error> {
        let mut sid_buffer = SidBuffer::with_capacity(self.sid_len as usize);
        let mut domain_buffer = LookupBuffer::with_capacity(self.domain_len as usize);
        let machine_name_ptr = self.machine_name.map_or(null(), |s| s.as_ptr());

        // SAFETY: Buffers are allocated with the sizes reported by the initial query.
        let result = unsafe {
            LookupAccountNameW(
                machine_name_ptr,
                self.account_name.as_ptr(),
                sid_buffer.as_mut_ptr().cast::<core::ffi::c_void>(),
                &raw mut self.sid_len,
                domain_buffer.as_mut_ptr(),
                &raw mut self.domain_len,
                &raw mut self.sid_type_raw,
            )
        };

        if result == 0 {
            // SAFETY: `GetLastError` is safe to call immediately after a failing Win32 call.
            return Err(Error::from(unsafe { GetLastError() }));
        }

        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "set initialized lengths after successful Win32 call"
        )]
        // SAFETY: The successful call initialized exactly these lengths.
        unsafe {
            sid_buffer.set_len(self.sid_len as usize);
            domain_buffer.set_len(self.domain_len as usize);
        }

        let sid_ref = unsafe {
            // SAFETY: LookupAccountNameW wrote a valid SID on success.
            crate::Sid::from_raw(sid_buffer.as_ptr().cast::<core::ffi::c_void>().cast_mut())
        };
        let sid = SecurityIdentifier::from(sid_ref);
        let domain = OsString::from_wide(domain_buffer.as_slice());
        let name = account_name_component(self.account_name);

        Ok(AccountLookup {
            sid,
            domain_name: DomainAndName::new(domain, name),
            sid_type_raw: self.sid_type_raw,
        })
    }
}

fn osstr_to_wide(os: &OsStr) -> Option<U16CString> {
    U16CString::from_os_str(os).ok()
}

fn account_name_component(account_name: &U16CString) -> OsString {
    let account_name = account_name.as_slice();
    #[expect(
        clippy::indexing_slicing,
        reason = "split index comes from the slice itself and is advanced by one code unit"
    )]
    let name = account_name
        .iter()
        .rposition(|&unit| unit == u16::from(b'\\'))
        .map_or(account_name, |index| &account_name[index + 1..]);
    OsString::from_wide(name)
}

impl SecurityIdentifier {
    /// Performs a lookup of an account name on the local machine.
    #[inline]
    #[must_use]
    pub fn lookup_local_account_name<S: AsRef<OsStr>>(
        account_name: S,
    ) -> Option<Result<AccountLookup, Error>> {
        osstr_to_wide(account_name.as_ref()).and_then(|account_name| {
            AccountLookupOperation::new(&account_name, None).map(AccountLookupOperation::process)
        })
    }

    /// Performs a lookup of an account name on a remote machine.
    #[inline]
    #[must_use]
    pub fn lookup_remote_account_name<M: AsRef<OsStr>, S: AsRef<OsStr>>(
        machine_name: M,
        account_name: S,
    ) -> Option<Result<AccountLookup, Error>> {
        osstr_to_wide(machine_name.as_ref()).and_then(|machine_name| {
            osstr_to_wide(account_name.as_ref()).and_then(|account_name| {
                AccountLookupOperation::new(&account_name, Some(&machine_name))
                    .map(AccountLookupOperation::process)
            })
        })
    }
}
