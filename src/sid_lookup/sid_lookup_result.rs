use num_enum::TryFromPrimitive;

use crate::{DomainAndName, SidType};

pub struct SidLookupResult {
    pub domain_name: DomainAndName,
    pub sid_type_raw: i32,
}

impl SidLookupResult {
    pub fn sid_type(&self) -> Result<SidType, num_enum::TryFromPrimitiveError<SidType>> {
        SidType::try_from_primitive(self.sid_type_raw)
    }
}
