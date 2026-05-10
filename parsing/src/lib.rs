#![cfg_attr(not(feature = "std"), no_std)]
//! SID parsing core functionality.
use core::str::FromStr;

use arrayvec::ArrayVec;
use thiserror::Error;
pub const MIN_SUBAUTHORITY_COUNT: u8 = 1;
const MIN_SUBAUTHORITY_COUNT_USIZE: usize = MIN_SUBAUTHORITY_COUNT as usize;
pub const MAX_SUBAUTHORITY_COUNT: u8 = 15;
const MAX_SUBAUTHORITY_COUNT_USIZE: usize = MAX_SUBAUTHORITY_COUNT as usize;
const SID_REVISION: u8 = 1;
const MAX_IDENTIFIER_AUTHORITY: u64 = 0xFFFF_FFFF_FFFF;

pub struct SidComponents {
    /// The SID identifier authority value.
    pub identifier_authority: [u8; 6],
    /// The SID sub-authority values.
    pub sub_authorities: ArrayVec<u32, MAX_SUBAUTHORITY_COUNT_USIZE>,
}

/// Error type returned when parsing a SID string fails due to an invalid format.
///
/// This is used by `FromStr<SecurityIdentifier>`.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InvalidSidFormat {
    #[error("SID must start with S")]
    InvalidPrefix,
    #[error("SID revision is missing")]
    MissingRevision,
    #[error("SID revision is invalid")]
    InvalidRevision,
    #[error("SID revision {revision} is invalid, expected {expected}")]
    UnsupportedRevision { revision: u64, expected: u8 },
    #[error("SID identifier authority is missing")]
    MissingIdentifierAuthority,
    #[error("SID identifier authority is invalid")]
    InvalidIdentifierAuthority,
    #[error("SID identifier authority {value} is greater than maximum {max}")]
    IdentifierAuthorityOutOfRange { value: u64, max: u64 },
    #[error("SID sub-authority at index {index} is invalid")]
    InvalidSubAuthority { index: usize },
    #[error("SID sub-authority at index {index} with value {value} is greater than maximum {max}")]
    SubAuthorityOutOfRange { index: usize, value: u64, max: u64 },
    #[error("SID has {count} sub-authorities, more than maximum {max}")]
    TooManySubAuthorities { count: usize, max: usize },
    #[error("SID must contain at least one sub-authority")]
    MissingSubAuthority,
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
            return Err(InvalidSidFormat::InvalidPrefix);
        }
        let revision = s_cmp
            .next()
            .ok_or(InvalidSidFormat::MissingRevision)?
            .parse::<u64>()
            .map_err(|_| InvalidSidFormat::InvalidRevision)?;

        if revision != u64::from(SID_REVISION) {
            return Err(InvalidSidFormat::UnsupportedRevision {
                revision,
                expected: SID_REVISION,
            });
        }

        let identifier_authority = s_cmp
            .next()
            .ok_or(InvalidSidFormat::MissingIdentifierAuthority)
            .and_then(parse_identifier_authority)?;
        let mut sub_authorities = ArrayVec::<u32, MAX_SUBAUTHORITY_COUNT_USIZE>::new();
        for (index, item) in s_cmp.enumerate() {
            let item = parse_sub_authority(index, item)?;
            sub_authorities.try_push(item).map_err(|_| {
                InvalidSidFormat::TooManySubAuthorities {
                    count: index + 1,
                    max: MAX_SUBAUTHORITY_COUNT_USIZE,
                }
            })?;
        }
        if sub_authorities.len() < MIN_SUBAUTHORITY_COUNT_USIZE {
            return Err(InvalidSidFormat::MissingSubAuthority);
        }

        Ok(Self {
            identifier_authority,
            sub_authorities,
        })
    }
}

fn parse_identifier_authority(s: &str) -> Result<[u8; 6], InvalidSidFormat> {
    let value = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| InvalidSidFormat::InvalidIdentifierAuthority)?
    } else {
        s.parse::<u64>()
            .map_err(|_| InvalidSidFormat::InvalidIdentifierAuthority)?
    };

    if value > MAX_IDENTIFIER_AUTHORITY {
        return Err(InvalidSidFormat::IdentifierAuthorityOutOfRange {
            value,
            max: MAX_IDENTIFIER_AUTHORITY,
        });
    }

    let bytes = value.to_be_bytes();
    #[expect(clippy::unwrap_used)]
    Ok(bytes[2..].try_into().unwrap())
}

fn parse_sub_authority(index: usize, s: &str) -> Result<u32, InvalidSidFormat> {
    let value = s
        .parse::<u64>()
        .map_err(|_| InvalidSidFormat::InvalidSubAuthority { index })?;

    if value > u64::from(u32::MAX) {
        return Err(InvalidSidFormat::SubAuthorityOutOfRange {
            index,
            value,
            max: u64::from(u32::MAX),
        });
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "value is checked against u32::MAX"
    )]
    Ok(value as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_identifier_authority() {
        let sid: SidComponents = "S-1-0x100000000-1".parse().unwrap();

        assert_eq!(sid.identifier_authority, [0, 1, 0, 0, 0, 0]);
        assert_eq!(sid.sub_authorities.as_slice(), [1]);
    }

    #[test]
    fn rejects_identifier_authority_above_48_bits() {
        assert!(matches!(
            "S-1-281474976710656-1".parse::<SidComponents>(),
            Err(InvalidSidFormat::IdentifierAuthorityOutOfRange {
                value: 281_474_976_710_656,
                max: MAX_IDENTIFIER_AUTHORITY,
            })
        ));
        assert!(matches!(
            "S-1-0x1000000000000-1".parse::<SidComponents>(),
            Err(InvalidSidFormat::IdentifierAuthorityOutOfRange {
                value: 281_474_976_710_656,
                max: MAX_IDENTIFIER_AUTHORITY,
            })
        ));
    }

    #[test]
    fn reports_invalid_sub_authority() {
        assert!(matches!(
            "S-1-5-not-a-rid".parse::<SidComponents>(),
            Err(InvalidSidFormat::InvalidSubAuthority { index: 0 })
        ));
    }

    #[test]
    fn reports_sub_authority_out_of_range() {
        assert!(matches!(
            "S-1-5-4294967296".parse::<SidComponents>(),
            Err(InvalidSidFormat::SubAuthorityOutOfRange {
                index: 0,
                value: 4_294_967_296,
                max: 4_294_967_295,
            })
        ));
    }
}
