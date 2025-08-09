use std::fmt;

#[derive(Debug)]
pub enum TokenError {
    OpenTokenFailed(u32),
    GetTokenSizeFailed,
    BufferTooSmall,
    GetTokenInfoFailed(u32),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::OpenTokenFailed(code) => {
                write!(f, "OpenProcessToken failed (error {})", code)
            }
            TokenError::GetTokenSizeFailed => {
                write!(f, "Failed to determine TokenUser buffer size")
            }
            TokenError::BufferTooSmall => write!(f, "Static buffer too small for TokenUser"),
            TokenError::GetTokenInfoFailed(code) => {
                write!(f, "GetTokenInformation failed (error {})", code)
            }
        }
    }
}

impl std::error::Error for TokenError {}
