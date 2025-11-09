use crate::sid::Sid;
mod token_error;
use core::mem::MaybeUninit;
use core::ptr;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
pub use token_error::TokenError;
use windows_sys::Win32::{
    Foundation::GetLastError,
    Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
pub trait GetCurrentSid: Sized
where
    for<'a> &'a Sid: Into<Self>,
{
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
            // Unexpected success: should fail to report size.

            use crate::TokenError;
            return Err(TokenError::GetTokenSizeFailed);
        }

        // --- Allocate buffer with reported size ------------------------------------
        let mut buffer = vec![0u8; size as usize];

        // SAFETY: Buffer pointer/length are consistent with allocation; size was set by the API.
        let second_ok = unsafe {
            GetTokenInformation(
                token_handle.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &raw mut size,
            )
        };

        if second_ok == 0 {
            // SAFETY: GetLastError can be called immediately after a failing FFI call.
            let err = unsafe { GetLastError() };
            return Err(TokenError::GetTokenInfoFailed(err));
        }
        #[expect(
            clippy::cast_ptr_alignment,
            reason = "read_unaligned handles unaligned access"
        )]
        let token_user_ptr = buffer.as_ptr().cast::<TOKEN_USER>();
        // SAFETY: TOKEN_USER is a plain data struct and can be read from a byte buffer.
        let sid_ptr = unsafe { ptr::addr_of!((*token_user_ptr).User.Sid) };
        // SAFETY: TOKEN_USER contains a PSID which is a pointer to a valid SID.
        let raw_sid = unsafe { ptr::read_unaligned(sid_ptr) };
        // SAFETY: get the user Sid from the raw pointer structure.
        let sid = unsafe { Sid::from_raw(raw_sid) };
        Ok(sid.into())
    }
}

impl<T> GetCurrentSid for T
where
    T: Sized,
    for<'a> &'a Sid: Into<T>,
{
}
