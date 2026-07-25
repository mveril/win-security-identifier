#![cfg(all(windows, feature = "std", feature = "alloc"))]

use win_security_identifier::{
    CloneSidFromRaw, GetCurrentSid, LookupAccountName, SecurityIdentifier, Sid, well_known,
};
use windows_sys::Win32::Security::PSID;

struct CustomSid(SecurityIdentifier);

impl AsRef<Sid> for CustomSid {
    fn as_ref(&self) -> &Sid {
        self.0.as_ref()
    }
}

// SAFETY: CustomSid copies the source SID into a SecurityIdentifier and does
// not retain the raw pointer.
unsafe impl CloneSidFromRaw for CustomSid {
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: Forwarding the caller's valid-PSID precondition.
        Self(unsafe { Sid::from_raw(raw) }.into())
    }
}

#[test]
fn external_clone_sid_from_raw_implementation_uses_windows_extensions() {
    fn assert_windows_extensions<T: GetCurrentSid + LookupAccountName>() {}
    assert_windows_extensions::<CustomSid>();

    let source = well_known::BUILTIN_ADMINISTRATORS.as_sid();
    // SAFETY: `source.as_raw()` remains valid for the duration of the call.
    let cloned = unsafe { CustomSid::clone_sid_from_raw(source.as_raw()) };

    assert_eq!(cloned.as_ref(), source);
    assert!(!core::ptr::addr_eq(cloned.as_ref(), source));
}
