use crate::sid::Sid;
mod token_error;
use super::CloneSidFromRaw;
use crate::utils::validate_sid_bytes_unaligned;
use core::mem::{MaybeUninit, align_of, size_of};
use core::ptr;
use std::boxed::Box;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::vec::Vec;
pub use token_error::TokenError;
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError},
    Security::{
        GetLengthSid, GetTokenInformation, SECURITY_MAX_SID_SIZE, TOKEN_GROUPS,
        TOKEN_INFORMATION_CLASS, TOKEN_PRIMARY_GROUP, TOKEN_QUERY, TOKEN_USER, TokenGroups,
        TokenPrimaryGroup, TokenUser,
    },
    System::{
        SystemServices::{SE_GROUP_LOGON_ID, SE_TOKEN_USER},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

#[allow(
    dead_code,
    reason = "Rust 1.85.0 dead_code does not count use from anonymous const assertions"
)]
const MAX_TOKEN_USER_BUFFER_SIZE: usize = size_of::<TOKEN_USER>() + SECURITY_MAX_SID_SIZE as usize;
const _: () = assert!(
    size_of::<SE_TOKEN_USER>() >= MAX_TOKEN_USER_BUFFER_SIZE,
    "SE_TOKEN_USER must fit TOKEN_USER plus the largest Windows SID"
);
const _: () = assert!(
    align_of::<SE_TOKEN_USER>() >= align_of::<TOKEN_USER>(),
    "SE_TOKEN_USER buffer must satisfy TOKEN_USER alignment"
);

type TokenInformationStorage = Vec<MaybeUninit<usize>>;

struct TokenInformationBuffer {
    storage: TokenInformationStorage,
}

impl TokenInformationBuffer {
    fn with_byte_capacity(capacity: usize) -> Self {
        let word_count = capacity.div_ceil(size_of::<usize>());
        Self {
            storage: TokenInformationStorage::with_capacity(word_count),
        }
    }

    #[allow(
        clippy::missing_const_for_fn,
        reason = "Vec::as_mut_ptr is not const-stable on the Rust 1.85.0 MSRV"
    )]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.storage.as_mut_ptr().cast()
    }

    #[allow(
        clippy::missing_const_for_fn,
        reason = "Vec::as_ptr is not const-stable on the Rust 1.85.0 MSRV"
    )]
    fn as_ptr(&self) -> *const u8 {
        self.storage.as_ptr().cast()
    }

    unsafe fn set_len(&mut self, len: usize) {
        let word_count = len.div_ceil(size_of::<usize>());
        // SAFETY: `MaybeUninit<usize>` does not require initialized contents.
        unsafe {
            self.storage.set_len(word_count);
        }
    }
}

const _: () = assert!(
    align_of::<usize>() >= align_of::<TOKEN_PRIMARY_GROUP>(),
    "TokenInformationBuffer must satisfy TOKEN_PRIMARY_GROUP alignment"
);
const _: () = assert!(
    align_of::<usize>() >= align_of::<TOKEN_GROUPS>(),
    "TokenInformationBuffer must satisfy TOKEN_GROUPS alignment"
);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TokenGroupAttributes(u32);

impl TokenGroupAttributes {
    #[allow(
        clippy::cast_sign_loss,
        reason = "SE_GROUP_LOGON_ID is a Windows bitflag exposed as i32"
    )]
    const LOGON_ID: Self = Self(SE_GROUP_LOGON_ID as u32);

    const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    const fn is_logon_id(self) -> bool {
        self.contains(Self::LOGON_ID)
    }
}

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
    #[inline]
    fn get_current_primary_group_sid() -> Result<Self, TokenError> {
        let token_handle = open_current_process_token()?;
        let buffer = query_token_information(token_handle.as_raw_handle(), TokenPrimaryGroup)?;
        #[allow(
            clippy::cast_ptr_alignment,
            reason = "TokenInformationBuffer storage alignment is checked against TOKEN_PRIMARY_GROUP"
        )]
        let primary_group = buffer.as_ptr().cast::<TOKEN_PRIMARY_GROUP>();
        // SAFETY: The buffer was returned by GetTokenInformation for TokenPrimaryGroup.
        let raw_sid = unsafe { (*primary_group).PrimaryGroup };
        if !is_supported_sid(raw_sid) {
            return Err(TokenError::InvalidTokenInfoSize);
        }
        // SAFETY: `raw_sid` points into `buffer`, which stays alive until after
        // `clone_sid_from_raw` returns.
        Ok(unsafe { Self::clone_sid_from_raw(raw_sid) })
    }

    /// Retrieves the group SIDs from the current process token.
    ///
    /// # Errors
    /// Returns a [`TokenError`] when opening or querying the process token fails.
    #[inline]
    fn get_current_user_group_sids() -> Result<Box<[Self]>, TokenError> {
        current_token_group_entries(|_, _| true)
            .map(|groups| groups.into_iter().map(|(sid, _)| sid).collect::<Box<[_]>>())
    }

    /// Retrieves the current logon SID, if present in the token groups.
    ///
    /// # Errors
    /// Returns a [`TokenError`] when opening or querying the process token fails.
    #[inline]
    fn get_current_logon_sid() -> Result<Option<Self>, TokenError> {
        let groups = current_token_group_entries(|_, attributes| attributes.is_logon_id())?;
        Ok(groups.into_iter().next().map(|(sid, _)| sid))
    }

    /// Checks whether the given SID is present in the current user SID or token group SIDs.
    ///
    /// # Errors
    /// Returns a [`TokenError`] when opening or querying the process token fails.
    #[inline]
    fn is_current_user_member_of(sid: &Sid) -> Result<bool, TokenError> {
        let current_user = Self::get_current_user_sid()?;
        if current_user.as_ref() == sid {
            return Ok(true);
        }
        current_token_group_entries::<Self>(|group_sid, _| group_sid == sid)
            .map(|groups| !groups.is_empty())
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

    // SAFETY: OpenProcessToken reported success; the handle is initialized.
    let raw_handle = unsafe { raw_handle_mu.assume_init() };
    // SAFETY: `raw_handle` is a valid owned handle obtained from the OS.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw_handle) })
}

fn query_token_information(
    token_handle: RawHandle,
    token_information_class: TOKEN_INFORMATION_CLASS,
) -> Result<TokenInformationBuffer, TokenError> {
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
    let mut buffer = TokenInformationBuffer::with_byte_capacity(len);
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

fn current_token_group_entries<T>(
    mut filter: impl FnMut(&Sid, TokenGroupAttributes) -> bool,
) -> Result<Box<[(T, TokenGroupAttributes)]>, TokenError>
where
    T: CloneSidFromRaw,
{
    let token_handle = open_current_process_token()?;
    let buffer = query_token_information(token_handle.as_raw_handle(), TokenGroups)?;
    #[allow(
        clippy::cast_ptr_alignment,
        reason = "TokenInformationBuffer storage alignment is checked against TOKEN_GROUPS"
    )]
    let token_groups = buffer.as_ptr().cast::<TOKEN_GROUPS>();
    let group_count = {
        // SAFETY: The buffer was returned by GetTokenInformation for TokenGroups.
        let raw_count = unsafe { (*token_groups).GroupCount };
        usize::try_from(raw_count).map_err(|_| TokenError::InvalidTokenInfoSize)?
    };
    // SAFETY: The buffer was returned by GetTokenInformation for TokenGroups.
    let groups_ptr = unsafe { (*token_groups).Groups.as_ptr() };
    // SAFETY: TOKEN_GROUPS is a variable-sized structure with GroupCount entries.
    let groups = unsafe { core::slice::from_raw_parts(groups_ptr, group_count) };
    Ok(groups
        .iter()
        .filter_map(|group| {
            if !is_supported_sid(group.Sid) {
                return None;
            }
            // SAFETY: TOKEN_GROUPS contains valid SID pointers for the lifetime of the buffer.
            let sid = unsafe { Sid::from_raw(group.Sid) };
            let attributes = TokenGroupAttributes::from_raw(group.Attributes);
            if filter(sid, attributes) {
                // SAFETY: TOKEN_GROUPS contains valid SID pointers for the lifetime of the buffer.
                Some((unsafe { T::clone_sid_from_raw(group.Sid) }, attributes))
            } else {
                None
            }
        })
        .collect())
}

fn is_supported_sid(raw_sid: windows_sys::Win32::Security::PSID) -> bool {
    if raw_sid.is_null() {
        return false;
    }
    // SAFETY: `raw_sid` comes from a Windows TOKEN_GROUPS entry. GetLengthSid
    // reads the SID header so the crate can validate the full supported layout.
    let len = unsafe { GetLengthSid(raw_sid) };
    if len == 0 {
        return false;
    }
    let Ok(len) = usize::try_from(len) else {
        return false;
    };
    // SAFETY: `raw_sid` points to `len` bytes according to GetLengthSid; the
    // crate validation below rejects unsupported SID layouts before cloning.
    let bytes = unsafe { core::slice::from_raw_parts(raw_sid.cast(), len) };
    validate_sid_bytes_unaligned(bytes).is_ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "Expect is not an issue in tests")]
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
