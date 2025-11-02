use thiserror::Error;

/// Errors that can occur when retrieving a Windows process token.
///
/// to report failures when working with the Windows security token API.
///
/// Each variant corresponds to a specific failure point.
#[derive(Debug, Error)]
pub enum TokenError {
    /// `OpenProcessToken` failed.
    ///
    /// Contains the Win32 error code returned by `GetLastError`.
    #[error("OpenProcessToken failed (error {0})")]
    OpenTokenFailed(u32),

    /// `GetTokenInformation` did not fail as expected when called with a zero-size buffer,
    /// so the required size could not be determined.
    #[error("Failed to determine TokenUser buffer size")]
    GetTokenSizeFailed,

    /// A fixed-size buffer provided for `TokenUser` information was too small.
    #[error("Static buffer too small for TokenUser")]
    BufferTooSmall,

    /// `GetTokenInformation` failed when retrieving `TokenUser`.
    ///
    /// Contains the Win32 error code returned by `GetLastError`.
    #[error("GetTokenInformation failed (error {0})")]
    GetTokenInfoFailed(u32),
}
