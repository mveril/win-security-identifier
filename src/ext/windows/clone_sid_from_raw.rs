use crate::{SecurityIdentifier, StackSid, sid::Sid};
use core::slice;
use windows_sys::Win32::Security::GetLengthSid;
use windows_sys::Win32::Security::PSID;

/// A type that can safely clone a SID from a raw Windows pointer.
///
/// # Safety
/// Implementations must clone the SID data and must not return a value that
/// borrows from, stores, or otherwise depends on the raw `PSID` passed to
/// [`CloneSidFromRaw::clone_sid_from_raw`]. Callers may pass pointers into
/// temporary buffers that become invalid immediately after the call returns.
///
/// Owning/cloning SID types satisfy this contract. Lifetime-carrying pointer
/// wrappers may also implement this trait when their implementation ensures the
/// returned pointer refers to storage that outlives the returned value.
///
/// Raw pointers do not implement this trait, because returning the temporary
/// token SID pointer directly would create a dangling pointer.
///
/// # Examples
///
/// ```
/// # #[cfg(windows)]
/// # {
/// use win_security_identifier::{CloneSidFromRaw, SecurityIdentifier, well_known};
///
/// let sid = well_known::BUILTIN_ADMINISTRATORS.as_sid();
/// let cloned = unsafe { SecurityIdentifier::clone_sid_from_raw(sid.as_raw()) };
///
/// assert_eq!(cloned.as_sid(), sid);
/// # }
/// ```
pub unsafe trait CloneSidFromRaw: Sized {
    /// Clones a SID from a raw Windows `PSID`.
    ///
    /// # Safety
    /// `sid` must be non-null and point to a valid SID for the duration of this
    /// call.
    #[must_use]
    unsafe fn clone_sid_from_raw(sid: PSID) -> Self;
}

unsafe fn raw_sid_bytes<'a>(raw: PSID) -> &'a [u8] {
    // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
    let len = unsafe { GetLengthSid(raw) };
    // SAFETY: `raw` points to a valid SID with `len` initialized bytes.
    unsafe { slice::from_raw_parts(raw.cast(), len as usize) }
}

unsafe fn stack_sid_from_raw(raw: PSID) -> StackSid {
    // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
    let bytes = unsafe { raw_sid_bytes(raw) };
    // SAFETY: The caller guarantees that `raw` points to a valid SID, and
    // `bytes` covers exactly that SID for the duration of this call.
    unsafe { StackSid::from_valid_bytes_unchecked(bytes) }
}

unsafe fn security_identifier_from_raw(raw: PSID) -> SecurityIdentifier {
    // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
    let bytes = unsafe { raw_sid_bytes(raw) };
    // SAFETY: The caller guarantees that `raw` points to a valid SID, and
    // `bytes` covers exactly that SID for the duration of this call.
    unsafe { SecurityIdentifier::from_valid_bytes_unchecked(bytes) }
}

// SAFETY: SecurityIdentifier copies the SID bytes into owned heap storage.
unsafe impl CloneSidFromRaw for SecurityIdentifier {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        unsafe { security_identifier_from_raw(raw) }
    }
}

// SAFETY: StackSid copies the SID bytes into owned stack storage.
unsafe impl CloneSidFromRaw for StackSid {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        unsafe { stack_sid_from_raw(raw) }
    }
}

// SAFETY: Box<Sid> copies the SID bytes into owned heap storage.
unsafe impl CloneSidFromRaw for Box<Sid> {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        unsafe { security_identifier_from_raw(raw).into() }
    }
}
