use crate::sid::Sid;
mod token_error;
use super::CloneSidFromRaw;
use core::mem::{MaybeUninit, align_of, size_of};
use core::ptr;
use std::boxed::Box;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::vec::Vec;
pub use token_error::TokenError;
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError},
    Security::{
        GetTokenInformation, SECURITY_MAX_SID_SIZE, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
        TOKEN_PRIMARY_GROUP, TOKEN_QUERY, TOKEN_USER, TokenGroups, TokenPrimaryGroup, TokenUser,
    },
    System::{
        SystemServices::{SE_GROUP_LOGON_ID, SE_TOKEN_USER},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

const MAX_TOKEN_USER_BUFFER_SIZE: usize = size_of::<TOKEN_USER>() + SECURITY_MAX_SID_SIZE as usize;
const LOGON_GROUP_ATTRIBUTE: u32 = SE_GROUP_LOGON_ID as u32;
const _: () = assert!(
    size_of::<SE_TOKEN_USER>() >= MAX_TOKEN_USER_BUFFER_SIZE,
    "SE_TOKEN_USER must fit TOKEN_USER plus the largest Windows SID"
);
const _: () = assert!(
    align_of::<SE_TOKEN_USER>() >= align_of::<TOKEN_USER>(),
    "SE_TOKEN_USER buffer must satisfy TOKEN_USER alignment"
);

pub trait GetCurrentSid: CloneSidFromRaw + AsRef<Sid> {
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

    /// Retrieves the current token primary group SID.
    ///
    /// # Errors
    /// Returns a [`TokenError`] when opening or querying the process token fails.
    fn get_current_primary_group_sid() -> Result<Self, TokenError> {
        let token_handle = open_current_process_token()?;
        let buffer = query_token_information(token_handle.as_raw_handle(), TokenPrimaryGroup)?;
        let primary_group = buffer.as_ptr().cast::<TOKEN_PRIMARY_GROUP>();
        // SAFETY: The buffer was returned by GetTokenInformation for TokenPrimaryGroup.
        let raw_sid = unsafe { (*primary_group).PrimaryGroup };
        // SAFETY: `raw_sid` points into `buffer`, which stays alive until after
        // `clone_sid_from_raw` returns.
        Ok(unsafe { Self::clone_sid_from_raw(raw_sid) })
    }

    /// Retrieves the group SIDs from the current process token.
    ///
    /// # Errors
    /// Returns a [`TokenError`] when opening or querying the process token fails.
    fn get_current_user_group_sids() -> Result<Box<[Self]>, TokenError> {
        current_token_group_entries()
            .map(|groups| groups.into_iter().map(|(sid, _)| sid).collect::<Box<[_]>>())
    }

    /// Retrieves the current logon SID, if present in the token groups.
    ///
    /// # Errors
    /// Returns a [`TokenError`] when opening or querying the process token fails.
    fn get_current_logon_sid() -> Result<Option<Self>, TokenError> {
        let groups = current_token_group_entries()?;
        Ok(groups
            .into_iter()
            .find(|(_, attributes)| (*attributes & LOGON_GROUP_ATTRIBUTE) == LOGON_GROUP_ATTRIBUTE)
            .map(|(sid, _)| sid))
    }

    /// Checks whether the given SID is present in the current user SID or token group SIDs.
    ///
    /// # Errors
    /// Returns a [`TokenError`] when opening or querying the process token fails.
    fn is_current_user_member_of(sid: &Sid) -> Result<bool, TokenError> {
        let current_user = Self::get_current_user_sid()?;
        if current_user.as_ref() == sid {
            return Ok(true);
        }
        Ok(Self::get_current_user_group_sids()?
            .iter()
            .any(|group| group.as_ref() == sid))
    }
}

impl<T> GetCurrentSid for T where T: CloneSidFromRaw + AsRef<Sid> {}

fn open_current_process_token() -> Result<OwnedHandle, TokenError> {
    let mut raw_handle_mu: MaybeUninit<RawHandle> = MaybeUninit::uninit();

    // SAFETY: GetCurrentProcess is side-effect free and can be called unconditionally.
    let process_handle = unsafe { GetCurrentProcess() };
    // SAFETY: FFI call; pointers are valid. We check the return value immediately.
    let open_ok =
        unsafe { OpenProcessToken(process_handle, TOKEN_QUERY, raw_handle_mu.as_mut_ptr()) };

    if open_ok == 0 {
        // SAFETY: GetLastError can be called immediately after a failing FFI call.
        let err = unsafe { GetLastError() };
        return Err(TokenError::OpenTokenFailed(err));
    }

    // SAFETY: OpenProcessToken reported success; the handle is initialized and owned.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw_handle_mu.assume_init()) })
}

fn query_token_information(
    token_handle: RawHandle,
    token_information_class: TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u8>, TokenError> {
    let mut size: u32 = 0;
    // SAFETY: Standard size-query pattern with null buffer and 0 length.
    let first_ok = unsafe {
        GetTokenInformation(
            token_handle,
            token_information_class,
            ptr::null_mut(),
            0,
            &raw mut size,
        )
    };
    if first_ok != 0 {
        return Err(TokenError::GetTokenSizeFailed);
    }
    // SAFETY: GetLastError can be called immediately after a failing FFI call.
    let size_error = unsafe { GetLastError() };
    if size_error != ERROR_INSUFFICIENT_BUFFER || size == 0 {
        return Err(TokenError::GetTokenSizeFailed);
    }

    let len = usize::try_from(size).map_err(|_| TokenError::InvalidTokenInfoSize)?;
    let mut buffer = Vec::<u8>::with_capacity(len);
    // SAFETY: The buffer has capacity for the requested token information.
    let second_ok = unsafe {
        GetTokenInformation(
            token_handle,
            token_information_class,
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
    let initialized_len = usize::try_from(size).map_err(|_| TokenError::InvalidTokenInfoSize)?;
    if initialized_len > len {
        return Err(TokenError::InvalidTokenInfoSize);
    }
    // SAFETY: GetTokenInformation initialized `size` bytes in the buffer on success.
    unsafe {
        buffer.set_len(initialized_len);
    }
    Ok(buffer)
}

fn current_token_group_entries<T>() -> Result<Vec<(T, u32)>, TokenError>
where
    T: CloneSidFromRaw,
{
    let token_handle = open_current_process_token()?;
    let buffer = query_token_information(token_handle.as_raw_handle(), TokenGroups)?;
    let token_groups = buffer.as_ptr().cast::<TOKEN_GROUPS>();
    let group_count = {
        // SAFETY: The buffer was returned by GetTokenInformation for TokenGroups.
        let raw_count = unsafe { (*token_groups).GroupCount };
        usize::try_from(raw_count).map_err(|_| TokenError::InvalidTokenInfoSize)?
    };
    let groups = {
        // SAFETY: TOKEN_GROUPS is a variable-sized structure with GroupCount entries.
        unsafe { core::slice::from_raw_parts((*token_groups).Groups.as_ptr(), group_count) }
    };
    Ok(groups
        .iter()
        .map(|group| {
            // SAFETY: TOKEN_GROUPS contains valid SID pointers for the lifetime of the buffer.
            let sid = unsafe { T::clone_sid_from_raw(group.Sid) };
            (sid, group.Attributes)
        })
        .collect())
}

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
