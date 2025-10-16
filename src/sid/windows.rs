use std::ffi::OsStr;

use widestring::WideCString;
use windows_sys::Win32::Security::PSID;

#[cfg(windows)]
use crate::sid_lookup::Error;
use crate::{SidLookupResult, SidType, sid_lookup::SidLookupOperation};

use super::Sid;

impl Sid {
    /// Creates a reference to a `Sid` from a raw `PSID` pointer.
    ///
    /// # Safety
    /// The `raw` pointer must point to a valid SID memory block with a correct layout
    /// and live at least as long as the returned reference.
    #[inline]
    pub const unsafe fn from_raw<'a>(raw: PSID) -> &'a Self {
        // Safety: Same precondition as the public API.
        unsafe { Self::from_raw_internal(raw as *const ()) }
    }

    /// Returns the underlying raw `PSID` pointer.
    #[inline]
    #[must_use]
    pub const fn as_raw(&self) -> PSID {
        // Direct cast is fine; avoids building a temporary slice.
        core::ptr::from_ref(self) as PSID
    }

    // -------- Internals -----------------------------------------------------

    /// Convert `OsStr` to `WideCString`, returning `None` on interior-nul errors.
    #[inline]
    fn osstr_to_wide(os: &OsStr) -> Option<WideCString> {
        WideCString::from_os_str(os).ok()
    }

    /// Internal: cheap “is known” probe on a given machine.
    /// Keep this minimal (no extra allocations beyond the optional machine name).
    #[inline]
    fn is_known_impl(&self, machine: Option<&WideCString>) -> bool {
        // If SidLookupOperation::new() is already the cheap probe,
        // keep it; otherwise we could introduce a dedicated `exists()` in the future.
        SidLookupOperation::new(self, machine).is_some()
    }

    /// Internal: full lookup on a given machine.
    #[cfg(windows)]
    #[inline]
    fn lookup_impl(&self, machine: Option<&WideCString>) -> Option<Result<SidLookupResult, Error>> {
        // Build once, then process. Keeps the public API tiny.
        SidLookupOperation::new(self, machine).map(SidLookupOperation::process)
    }

    // -------- Public API ----------------------------------------------------

    /// Checks if this SID is known on the local machine.
    #[inline]
    #[must_use]
    pub fn is_known_local_sid(&self) -> bool {
        self.is_known_impl(None)
    }

    /// Checks if this SID is known on a remote machine.
    ///
    /// Accepts any `AsRef<OsStr>` to avoid forcing callers to build an `OsStr`.
    #[inline]
    #[must_use]
    pub fn is_known_remote_sid<S: AsRef<OsStr>>(&self, machine_name: S) -> bool {
        Self::osstr_to_wide(machine_name.as_ref())
            .is_some_and(|wide: widestring::U16CString| self.is_known_impl(Some(&wide)))
    }

    /// Performs a lookup of this SID on the local machine.
    #[inline]
    #[must_use]
    pub fn lookup_local_sid(&self) -> Option<Result<SidLookupResult, Error>> {
        self.lookup_impl(None)
    }

    /// Performs a lookup of this SID on a remote machine.
    ///
    /// Accepts any `AsRef<OsStr>` to be ergonomic for callers.
    #[inline]
    #[must_use]
    pub fn lookup_remote_sid<S: AsRef<OsStr>>(
        &self,
        machine_name: S,
    ) -> Option<Result<SidLookupResult, Error>> {
        Self::osstr_to_wide(machine_name.as_ref()).and_then(|w| self.lookup_impl(Some(&w)))
    }

    /// Returns the `SidType` for this SID on the local machine (if lookup succeeds).
    ///
    /// `None` means the probe failed (e.g., unknown SID or API error).
    /// `Some(Err(_))` means the raw type could not be converted into `SidType`.
    #[inline]
    #[must_use]
    pub fn local_sid_type(
        &self,
    ) -> Option<Result<SidType, num_enum::TryFromPrimitiveError<SidType>>> {
        // Avoid re-allocating buffers: rely on the “new()” probe that already gathers raw type.
        SidLookupOperation::new(self, None).map(|op| SidType::try_from(op.sid_type_raw))
    }

    /// Returns the `SidType` for this SID on a remote machine (if lookup succeeds).
    #[inline]
    #[must_use]
    pub fn remote_sid_type<S: AsRef<OsStr>>(
        &self,
        machine_name: S,
    ) -> Option<Result<SidType, num_enum::TryFromPrimitiveError<SidType>>> {
        Self::osstr_to_wide(machine_name.as_ref()).and_then(|w| {
            SidLookupOperation::new(self, Some(&w)).map(|op| SidType::try_from(op.sid_type_raw))
        })
    }
}
