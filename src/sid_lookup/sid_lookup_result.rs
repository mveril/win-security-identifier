use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

use crate::{DomainAndName, SidType};
/// This struct represent the result of a [SID lookup operation](https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-lookupaccountsidw).
pub struct SidLookupResult {
    /// The domain and name associated with the SID.
    pub domain_name: DomainAndName,
    /// The raw SID type value.
    pub sid_type_raw: i32,
}

impl SidLookupResult {
    /// Get the SID type as an enum.
    /// # Errors
    /// Return a [`TryFromPrimitiveError<SidType>`] error if the raw SID type value is unknown.
    #[inline]
    pub fn sid_type(&self) -> Result<SidType, TryFromPrimitiveError<SidType>> {
        SidType::try_from_primitive(self.sid_type_raw)
    }
}
