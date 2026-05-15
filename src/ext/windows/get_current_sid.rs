use crate::{SecurityIdentifier, StackSid, sid::Sid};
mod token_error;
use core::mem::{MaybeUninit, align_of, size_of};
use core::ptr;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
pub use token_error::TokenError;
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError},
    Security::{
        GetTokenInformation, PSID, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    System::{
        SystemServices::SE_TOKEN_USER,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

const MAX_TOKEN_USER_BUFFER_SIZE: usize = size_of::<TOKEN_USER>() + SECURITY_MAX_SID_SIZE as usize;
const _: () = assert!(
    size_of::<SE_TOKEN_USER>() >= MAX_TOKEN_USER_BUFFER_SIZE,
    "SE_TOKEN_USER must fit TOKEN_USER plus the largest Windows SID"
);
const _: () = assert!(
    align_of::<SE_TOKEN_USER>() >= align_of::<TOKEN_USER>(),
    "SE_TOKEN_USER buffer must satisfy TOKEN_USER alignment"
);

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
    unsafe fn clone_sid_from_raw(sid: PSID) -> Self;
}

// SAFETY: SecurityIdentifier copies the SID bytes into owned heap storage.
unsafe impl CloneSidFromRaw for SecurityIdentifier {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        let sid = unsafe { Sid::from_raw(raw) };
        sid.into()
    }
}

// SAFETY: StackSid copies the SID bytes into owned stack storage.
unsafe impl CloneSidFromRaw for StackSid {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        let sid = unsafe { Sid::from_raw(raw) };
        sid.into()
    }
}

// SAFETY: Box<Sid> copies the SID bytes into owned heap storage.
unsafe impl CloneSidFromRaw for Box<Sid> {
    #[inline]
    unsafe fn clone_sid_from_raw(raw: PSID) -> Self {
        // SAFETY: The caller guarantees `raw` points to a valid SID for this call.
        unsafe { SecurityIdentifier::clone_sid_from_raw(raw).into() }
    }
}

pub trait GetCurrentSid: CloneSidFromRaw {
    /// Retrieves the current user's SID from the process token (Windows only).
    ///
    /// # Errors
    /// Returns a `TokenError` when opening the token or querying it fails.
    ///
    /// # Examples
    /// ```no_run
    /// # #[cfg(windows)]
    /// # {
    /// # use win_security_identifier::SecurityIdentifier;
    /// use win_security_identifier::GetCurrentSid;
    /// let sid = SecurityIdentifier::get_current_user_sid().unwrap();
    /// println!("{}", sid);
    /// # }
    /// ```
    #[allow(
        clippy::missing_inline_in_public_items,
        reason = "Too complex to inline"
    )]
    fn get_current_user_sid() -> Result<Self, TokenError> {
        // --- Open the process token ------------------------------------------------
        let mut raw_handle_mu: MaybeUninit<RawHandle> = MaybeUninit::uninit();

        // SAFETY: GetCurrentProcess is side-effect free and can be called unconditionally.
        let process_handle = unsafe { GetCurrentProcess() };
        // SAFETY: FFI call; pointers are valid. We check the return value immediately.
        let open_ok =
            unsafe { OpenProcessToken(process_handle, TOKEN_QUERY, raw_handle_mu.as_mut_ptr()) };

        if open_ok == 0 {
            // SAFETY: GetLastError is side-effect free and can be called unconditionally.

            use crate::TokenError;
            // SAFETY: GetLastError can be called immediately after a failing FFI call.
            let err = unsafe { GetLastError() };
            return Err(TokenError::OpenTokenFailed(err));
        }

        // SAFETY: OpenProcessToken reported success; the handle is initialized.
        let raw_handle: RawHandle = unsafe { raw_handle_mu.assume_init() };

        // SAFETY: `raw_handle` is a valid owned handle obtained from the OS.
        let token_handle: OwnedHandle = unsafe { OwnedHandle::from_raw_handle(raw_handle) };

        // --- First GetTokenInformation to obtain required size ---------------------
        let mut size: u32 = 0;
        // SAFETY: Standard size-query pattern with null buffer and 0 length.
        let first_ok = unsafe {
            GetTokenInformation(
                token_handle.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &raw mut size,
            )
        };

        if first_ok != 0 {
            // Unexpected success: a zero-size buffer should only report the required size.
            return Err(TokenError::GetTokenSizeFailed);
        }
        // SAFETY: GetLastError can be called immediately after a failing FFI call.
        let size_error = unsafe { GetLastError() };
        if size_error != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return Err(TokenError::GetTokenSizeFailed);
        }

        // --- Allocate buffer with reported size ------------------------------------
        if size as usize > size_of::<SE_TOKEN_USER>() {
            return Err(TokenError::BufferTooSmall);
        }
        // Microsoft documents SE_TOKEN_USER as the stack-allocatable structure for
        // the largest TokenUser result. Using it directly gives the buffer the same
        // size and alignment as that C structure, without a heap allocation.
        let mut buffer = MaybeUninit::<SE_TOKEN_USER>::uninit();
        let token_user_ptr = buffer.as_mut_ptr().cast::<TOKEN_USER>();

        // SAFETY: `buffer` is writable stack storage with TOKEN_USER-compatible
        // alignment by the const assertion above. `size` was reported by the API
        // and checked to fit in SE_TOKEN_USER.
        let second_ok = unsafe {
            GetTokenInformation(
                token_handle.as_raw_handle(),
                TokenUser,
                token_user_ptr.cast(),
                size,
                &raw mut size,
            )
        };
        if second_ok == 0 {
            // SAFETY: GetLastError can be called immediately after a failing FFI call.
            let err = unsafe { GetLastError() };
            return Err(TokenError::GetTokenInfoFailed(err));
        }
        // SAFETY: TOKEN_USER contains a PSID which is valid for this call.
        let raw_sid = unsafe { (*token_user_ptr).User.Sid };
        // SAFETY: `raw_sid` points into `buffer`, which stays alive until after
        // `clone_sid_from_raw` returns.
        Ok(unsafe { Self::clone_sid_from_raw(raw_sid) })
    }
}

impl<T> GetCurrentSid for T where T: CloneSidFromRaw {}

#[cfg(test)]
mod tests {
    use super::{MAX_TOKEN_USER_BUFFER_SIZE, SE_TOKEN_USER, TOKEN_USER};
    use core::mem::{align_of, size_of};
    use windows_sys::Win32::Security::{PSID, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES};

    #[test]
    fn token_user_buffer_layout_matches_windows_sys() {
        let token_user_buffer_size = size_of::<TOKEN_USER>() + SECURITY_MAX_SID_SIZE as usize;

        assert_eq!(
            MAX_TOKEN_USER_BUFFER_SIZE, token_user_buffer_size,
            "production TOKEN_USER buffer calculation must match windows-sys layout"
        );
        assert!(
            size_of::<SE_TOKEN_USER>() >= token_user_buffer_size,
            "SE_TOKEN_USER has {} bytes, needs {token_user_buffer_size}",
            size_of::<SE_TOKEN_USER>()
        );
        assert!(
            align_of::<SE_TOKEN_USER>() >= align_of::<TOKEN_USER>(),
            "SE_TOKEN_USER alignment ({}) must cover TOKEN_USER alignment ({})",
            align_of::<SE_TOKEN_USER>(),
            align_of::<TOKEN_USER>()
        );
        assert_eq!(
            align_of::<TOKEN_USER>(),
            align_of::<SID_AND_ATTRIBUTES>(),
            "TOKEN_USER is a wrapper around SID_AND_ATTRIBUTES"
        );
        assert_eq!(
            align_of::<SID_AND_ATTRIBUTES>(),
            align_of::<PSID>(),
            "SID_AND_ATTRIBUTES alignment is driven by its PSID member"
        );
    }
}
