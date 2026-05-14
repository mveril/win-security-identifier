use crate::Sid;

use super::Error;
use super::SidLookup;
use super::SidType;
use super::domain_and_name::DomainAndName;
use core::ptr::{null, null_mut};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use smallvec::SmallVec;
use std::{ffi::OsString, os::windows::ffi::OsStringExt};
use widestring::U16CString;
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::{Foundation::GetLastError, Security::LookupAccountSidW};

type LookupBuffer = SmallVec<[u16; 256]>;

pub struct SidLookupOperation<'a> {
    sid: &'a Sid,
    machine_name: Option<&'a U16CString>,
    name_len: u32,
    domain_len: u32,
    sid_type_raw: i32,
}

impl<'a> SidLookupOperation<'a> {
    pub fn new(sid: &'a Sid, machine_name: Option<&'a U16CString>) -> Option<Self> {
        let mut name_len = 0u32;
        let mut domain_len = 0u32;
        let mut sid_type_raw = 0i32;

        // Safety: All parameters of `LookupAccountSidW` are valid.
        let result = unsafe {
            LookupAccountSidW(
                machine_name.as_ref().map_or(null_mut(), |s| s.as_ptr()),
                sid.as_raw(),
                null_mut(),
                &raw mut name_len,
                null_mut(),
                &raw mut domain_len,
                &raw mut sid_type_raw,
            )
        };
        if result != 0 {
            return None;
        }
        // Safety: `GetLastError` is always safe to call.
        let err = Error::from(unsafe { GetLastError() });
        if err != Error::Other(ERROR_INSUFFICIENT_BUFFER) {
            return None;
        }

        Some(Self {
            sid,
            machine_name,
            name_len,
            domain_len,
            sid_type_raw,
        })
    }

    fn core_process<T>(
        mut self,
        on_success: impl FnOnce(u32, u32, i32, LookupBuffer, LookupBuffer) -> T,
    ) -> Result<T, Error> {
        let mut name_buffer = LookupBuffer::with_capacity(self.name_len as usize);
        let mut domain_buffer = LookupBuffer::with_capacity(self.domain_len as usize);
        // Safety: All parameters of `LookupAccountSidW` are valid.
        let machine_name_ptr = self.machine_name.map_or(null(), |s| s.as_ptr());
        // Safety: All parameters of `LookupAccountSidW` are valid.
        let result = unsafe {
            LookupAccountSidW(
                machine_name_ptr,
                self.sid.as_raw(),
                name_buffer.as_mut_ptr(),
                &raw mut self.name_len,
                domain_buffer.as_mut_ptr(),
                &raw mut self.domain_len,
                &raw mut self.sid_type_raw,
            )
        };
        let result = (result == 0).then(|| {
            // Safety: `GetLastError` is always safe to call.
            let last_error = unsafe { GetLastError() };
            Error::from(last_error)
        });
        match result {
            Some(Error::Other(ERROR_INSUFFICIENT_BUFFER)) => self.core_process(on_success),
            Some(err) => Err(err),
            None => Ok(on_success(
                self.name_len,
                self.domain_len,
                self.sid_type_raw,
                name_buffer,
                domain_buffer,
            )),
        }
    }

    pub(crate) fn process(self) -> Result<SidLookup, Error> {
        self.core_process(
            |name_len, domain_len, sid_type_raw, mut name_buffer, mut domain_buffer| {
                #[expect(
                    clippy::multiple_unsafe_ops_per_block,
                    reason = "Same operation so same safety doc"
                )]
                // Safety: The buffers was allocated with the correct capacity and the call to `LookupAccountSidW` fill the buffers.
                unsafe {
                    name_buffer.set_len(name_len as usize);
                    domain_buffer.set_len(domain_len as usize);
                }
                let name = OsString::from_wide(name_buffer.as_slice());
                let domain = OsString::from_wide(domain_buffer.as_slice());
                SidLookup {
                    domain_name: DomainAndName::new(domain, name),
                    sid_type_raw,
                }
            },
        )
    }

    pub(crate) fn process_type(self) -> Option<Result<SidType, TryFromPrimitiveError<SidType>>> {
        self.core_process(|_, _, sid_type_raw, _, _| SidType::try_from_primitive(sid_type_raw))
            .ok()
    }
}
