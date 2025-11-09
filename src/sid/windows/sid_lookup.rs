use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
mod sid_type;
pub use sid_type::SidType;
pub mod domain_and_name;
pub use domain_and_name::DomainAndName;
mod sid_lookup_operation;
pub(super) use sid_lookup_operation::SidLookupOperation;
pub mod error;
pub use error::Error;
/// This struct represent the result of a [SID lookup operation](https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-lookupaccountsidw).
pub struct SidLookup {
    /// The domain and name associated with the SID.
    pub domain_name: DomainAndName,
    /// The raw SID type value.
    pub sid_type_raw: i32,
}

impl SidLookup {
    /// Get the SID type as an enum.
    /// # Errors
    /// Return a [`TryFromPrimitiveError<SidType>`] error if the raw SID type value is unknown.
    #[inline]
    pub fn sid_type(&self) -> Result<SidType, TryFromPrimitiveError<SidType>> {
        SidType::try_from_primitive(self.sid_type_raw)
    }
}
