use crate::{SecurityIdentifier, SidIdentifierAuthority, StackSid, sid::Sid};
use core::ptr;
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

#[allow(
    clippy::indexing_slicing,
    clippy::multiple_unsafe_ops_per_block,
    reason = "The unsafe trait contract guarantees the raw SID byte layout and length"
)]
unsafe fn stack_sid_from_raw(raw: PSID) -> StackSid {
    // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
    let bytes = unsafe { raw_sid_bytes(raw) };

    let mut identifier_authority = [0_u8; 6];
    // SAFETY: The trait contract requires `bytes` to contain a valid SID.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr().add(2), identifier_authority.as_mut_ptr(), 6);
    }

    // SAFETY: The trait contract requires `bytes` to contain a valid SID.
    let sub_authority_count = unsafe { *bytes.as_ptr().add(1) as usize };
    let mut sub_authorities = [0_u32; parsing::MAX_SUBAUTHORITY_COUNT as usize];
    let mut index = 0;
    while index < sub_authority_count {
        let offset = 8 + (index * size_of::<u32>());
        // SAFETY: The trait contract requires `bytes` to contain a valid SID,
        // and Windows stores SID sub-authorities as little-endian u32 values.
        sub_authorities[index] =
            u32::from_le(unsafe { ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<u32>()) });
        index += 1;
    }

    // SAFETY: The trait contract requires a valid SID, so the count is valid.
    unsafe {
        StackSid::new_unchecked(
            SidIdentifierAuthority::new(identifier_authority),
            sub_authorities.get_unchecked(..sub_authority_count),
        )
    }
}

// SAFETY: SecurityIdentifier copies the SID bytes into owned heap storage.
unsafe impl CloneSidFromRaw for SecurityIdentifier {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        let sid = unsafe { stack_sid_from_raw(raw) };
        sid.as_sid().into()
    }
}

// SAFETY: StackSid copies the SID bytes into owned stack storage.
unsafe impl CloneSidFromRaw for StackSid {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        let sid = unsafe { stack_sid_from_raw(raw) };
        sid.as_sid().into()
    }
}

// SAFETY: Box<Sid> copies the SID bytes into owned heap storage.
unsafe impl CloneSidFromRaw for Box<Sid> {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        let sid = unsafe { stack_sid_from_raw(raw) };
        sid.as_sid().into()
    }
}
