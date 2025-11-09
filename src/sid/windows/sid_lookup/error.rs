use core::num::NonZeroU32;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_INVALID_SID, ERROR_NO_SUCH_DOMAIN,
    ERROR_NONE_MAPPED, ERROR_TRUSTED_DOMAIN_FAILURE,
};

/// Errors that can be returned by `LookupAccountSidW`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// The SID is syntactically invalid.
    InvalidSid,
    /// One or more parameters are invalid.
    InvalidParameter,
    /// The SID is not mapped to any account on the target system.
    NoneMapped,
    /// Access denied while trying to look up the SID (rare for this API, but possible).
    AccessDenied,
    /// The specified computer name (server) could not be found/reached.
    NetworkPathNotFound,
    /// The specified domain either does not exist or could not be contacted.
    NoSuchDomain,
    /// Trust relationship issues with the domain.
    TrustedRelationshipFailure,
    /// Any other Win32 error code not handled above.
    Other(u32),
}

impl From<NonZeroU32> for Error {
    #[inline]
    fn from(code: NonZeroU32) -> Self {
        let code = code.get();
        match code {
            // Common (documentés pour LookupAccountSidW)
            ERROR_INVALID_SID => Self::InvalidSid, // ERROR_INVALID_SID
            ERROR_INVALID_PARAMETER => Self::InvalidParameter, // ERROR_INVALID_PARAMETERs
            ERROR_NONE_MAPPED => Self::NoneMapped, // ERROR_NONE_MAPPED
            ERROR_ACCESS_DENIED => Self::AccessDenied, // ERROR_ACCESS_DENIED
            53 => Self::NetworkPathNotFound,       // ERROR_BAD_NETPATH
            ERROR_NO_SUCH_DOMAIN => Self::NoSuchDomain, // ERROR_NO_SUCH_DOMAIN
            ERROR_TRUSTED_DOMAIN_FAILURE => Self::TrustedRelationshipFailure, // ERROR_TRUSTED_RELATIONSHIP_FAILURE
            other => Self::Other(other),
        }
    }
}
