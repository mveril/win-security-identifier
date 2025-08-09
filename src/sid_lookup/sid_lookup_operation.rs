use super::SidLookupResult;
use crate::sid_type::SidType;
use crate::{DomainAndName, Sid};
use num_enum::TryFromPrimitive;
use smallvec::SmallVec;
use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr::null_mut};
use widestring::U16CString;
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError},
    Security::*,
};

pub(crate) struct SidLookupOperation<'a> {
    pub sid: &'a Sid,
    pub machine_name: Option<&'a U16CString>,
    pub name_len: u32,
    pub domain_len: u32,
    pub sid_type_raw: i32,
}

impl<'a> SidLookupOperation<'a> {
    pub fn new(sid: &'a Sid, machine_name: Option<&'a U16CString>) -> Option<Self> {
        let mut name_len = 0u32;
        let mut domain_len = 0u32;
        let mut sid_type_raw = 0i32;

        unsafe {
            let result = LookupAccountSidW(
                machine_name
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(null_mut()),
                sid.as_raw(),
                null_mut(),
                &mut name_len,
                null_mut(),
                &mut domain_len,
                &mut sid_type_raw,
            );

            let err = GetLastError();
            if result == 0 && err != ERROR_INSUFFICIENT_BUFFER {
                eprintln!("LookupAccountSidW failed: {}", err);
                return None;
            }
        }

        Some(Self {
            sid,
            machine_name,
            name_len,
            domain_len,
            sid_type_raw,
        })
    }

    pub fn process(mut self) -> SidLookupResult {
        unsafe {
            let mut name_buffer = SmallVec::<[u16; 256]>::with_capacity(self.name_len as usize);
            let mut domain_buffer = SmallVec::<[u16; 256]>::with_capacity(self.name_len as usize);
            let result = LookupAccountSidW(
                self.machine_name
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(null_mut()),
                self.sid.as_raw(),
                name_buffer.as_mut_ptr(),
                &mut self.name_len,
                domain_buffer.as_mut_ptr(),
                &mut self.domain_len,
                &mut self.sid_type_raw,
            );
            let err = GetLastError();
            let result = if result == 0 {
                Some(GetLastError())
            } else {
                None
            };
            match result {
                Some(ERROR_INSUFFICIENT_BUFFER) => self.process(),
                Some(err) => {
                    panic!("LookupAccountSidW failed: {}", err);
                }
                None => {
                    name_buffer.set_len(self.name_len as usize);
                    domain_buffer.set_len(self.domain_len as usize);
                    let name = OsString::from_wide(name_buffer.as_slice());
                    let domain = OsString::from_wide(domain_buffer.as_slice());
                    SidLookupResult {
                        domain_name: DomainAndName::new(domain, name),
                        sid_type_raw: self.sid_type_raw,
                    }
                }
            }
        }
    }
}
