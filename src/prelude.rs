//! Common imports for working with Windows Security Identifiers.

pub use crate::{
    AccountSid, ConstSid, ExtendSubAuthoritiesError, InvalidSidBinaryFormat, InvalidSidFormat,
    InvalidSidParts, NotAccountSid, OwnedSid, PopSubAuthoritiesError, PopSubAuthorityError,
    PoppedSubAuthorities, PushSubAuthorityError, Sid, SidClassification, SidIdentifierAuthority,
    StackSid, TruncateSubAuthoritiesError,
};

#[cfg(feature = "alloc")]
pub use crate::SecurityIdentifier;
#[cfg(feature = "macro")]
pub use crate::sid;
#[cfg(all(windows, feature = "std"))]
pub use crate::{CloneSidFromRaw, GetCurrentSid, LookupAccountName, TokenError};
