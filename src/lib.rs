mod security_identifier;

mod sid;

pub use security_identifier::SecurityIdentifier;
pub use sid::Sid;
#[cfg(not(feature = "nightly"))]
pub(crate) mod polyfils_ptr;
use security_identifier::SidSizeInfo;
mod sid_identifier_authority;
#[cfg(test)]
pub(crate) use security_identifier::test::arb_security_identifier;
pub use sid_identifier_authority::SidIdentifierAuthority;
#[cfg(test)]
pub(crate) use sid_identifier_authority::test::arb_identifier_authority;
mod const_sid;
pub use const_sid::ConstSid;
mod domain_and_name;
#[cfg(windows)]
mod sid_lookup;
pub use domain_and_name::DomainAndName;
#[cfg(windows)]
pub use sid_lookup::SidLookupResult;
#[cfg(windows)]
mod sid_type;
#[cfg(windows)]
pub use sid_type::SidType;
pub(crate) mod utils;
