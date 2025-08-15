use core::fmt::{self, Display};
use core::str::FromStr;

use arrayvec::ArrayVec;
use thiserror::Error;

pub struct SidComponents {
    /// The SID revision value, generally 1.
    pub revision: u8,
    /// The SID identifier authority value.
    pub identifier_authority: [u8; 6],
    /// The SID sub-authority values.
    pub sub_authority: ArrayVec<u32, 16>,
}

/// Error type returned when parsing a SID string fails due to an invalid format.
///
/// This is used by `FromStr<SecurityIdentifier>`.
#[derive(Debug, Error)]
pub struct InvalidSidFormat;

impl Display for InvalidSidFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invalid format for Sid")
    }
}

impl FromStr for SidComponents {
    type Err = InvalidSidFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s_cmp = s.split("-");
        if !s_cmp
            .next()
            .map(|head| head.eq_ignore_ascii_case("s"))
            .unwrap_or(false)
        {
            return Err(InvalidSidFormat);
        }
        let revision = s_cmp
            .next()
            .ok_or(InvalidSidFormat)?
            .parse::<u8>()
            .map_err(|_| InvalidSidFormat)?;

        let identifier_authority = s_cmp
            .next()
            .ok_or(InvalidSidFormat)
            .and_then(|s| s.parse::<u64>().map_err(|_| InvalidSidFormat))
            .map(|value| {
                let bytes = value.to_be_bytes();
                let array: [u8; 6] = bytes[2..].try_into().unwrap();
                array
            })?;
        let mut sub_authority = ArrayVec::<u32, 16>::new();
        for item in s_cmp {
            let item = item.parse::<u32>().map_err(|_| InvalidSidFormat)?;
            sub_authority.try_push(item).map_err(|_| InvalidSidFormat)?;
        }

        Ok(Self {
            revision,
            identifier_authority,
            sub_authority,
        })
    }
}
