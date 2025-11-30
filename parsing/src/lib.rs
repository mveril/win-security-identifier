#![cfg_attr(not(feature = "std"), no_std)]
//! SID parsing core functionality.
use core::fmt::{self, Display};
use core::str::FromStr;

use arrayvec::ArrayVec;
use thiserror::Error;
pub const MIN_SUBAUTHORITY_COUNT: u8 = 1;
const MIN_SUBAUTHORITY_COUNT_USIZE: usize = MIN_SUBAUTHORITY_COUNT as usize;
pub const MAX_SUBAUTHORITY_COUNT: u8 = 15;
const MAX_SUBAUTHORITY_COUNT_USIZE: usize = MAX_SUBAUTHORITY_COUNT as usize;

pub struct SidComponents {
    /// The SID identifier authority value.
    pub identifier_authority: [u8; 6],
    /// The SID sub-authority values.
    pub sub_authority: ArrayVec<u32, MAX_SUBAUTHORITY_COUNT_USIZE>,
}

/// Error type returned when parsing a SID string fails due to an invalid format.
///
/// This is used by `FromStr<SecurityIdentifier>`.
#[derive(Debug, Error)]
pub struct InvalidSidFormat;

impl Display for InvalidSidFormat {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invalid format for Sid")
    }
}

impl FromStr for SidComponents {
    type Err = InvalidSidFormat;
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s_cmp = s.split('-');
        if !s_cmp
            .next()
            .is_some_and(|head| head.eq_ignore_ascii_case("s"))
        {
            return Err(InvalidSidFormat);
        }
        let revision = s_cmp
            .next()
            .ok_or(InvalidSidFormat)?
            .parse::<u8>()
            .map_err(|_| InvalidSidFormat)?;

        if revision != 1 {
            return Err(InvalidSidFormat);
        }

        let identifier_authority = s_cmp
            .next()
            .ok_or(InvalidSidFormat)
            .and_then(|s| s.parse::<u64>().map_err(|_| InvalidSidFormat))
            .map(|value| {
                let bytes = value.to_be_bytes();
                #[expect(clippy::unwrap_used)]
                bytes[2..].try_into().unwrap()
            })?;
        let mut sub_authority = ArrayVec::<u32, MAX_SUBAUTHORITY_COUNT_USIZE>::new();
        for item in s_cmp {
            let item = item.parse::<u32>().map_err(|_| InvalidSidFormat)?;
            sub_authority.try_push(item).map_err(|_| InvalidSidFormat)?;
        }
        if sub_authority.len() < MIN_SUBAUTHORITY_COUNT_USIZE {
            return Err(InvalidSidFormat);
        }

        Ok(Self {
            identifier_authority,
            sub_authority,
        })
    }
}
