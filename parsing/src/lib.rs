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
    UnsupportedRevision { revision: u8, expected: u8 },
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
            .parse::<u8>()
            .map_err(|_| InvalidSidFormat::InvalidRevision)?;

        if revision != SID_REVISION {
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
    use proptest::prelude::*;

    #[test]
    fn parses_hex_identifier_authority() {
        let result = "S-1-0x100000000-1".parse::<SidComponents>();

        assert!(result.is_ok());
        assert_eq!(
            result.as_ref().map(|sid| sid.identifier_authority),
            Ok([0, 1, 0, 0, 0, 0])
        );
        assert_eq!(
            result.as_ref().map(|sid| sid.sub_authorities.as_slice()),
            Ok([1].as_slice())
        );
    }

    proptest! {
        #[test]
        fn rejects_invalid_prefix(prefix in "[^sS-]{0,8}") {
            let sid = format!("{prefix}-1-5-32");

            prop_assert_eq!(
                sid.parse::<SidComponents>().err(),
                Some(InvalidSidFormat::InvalidPrefix)
            );
        }

        #[test]
        fn rejects_unsupported_revision(revision in prop_oneof![Just(0u8), 2u8..=u8::MAX]) {
            let sid = format!("S-{revision}-5-32");

            prop_assert_eq!(
                sid.parse::<SidComponents>().err(),
                Some(InvalidSidFormat::UnsupportedRevision {
                    revision,
                    expected: SID_REVISION,
                })
            );
        }

        #[test]
        fn accepts_decimal_identifier_authorities(value in 0u64..=MAX_IDENTIFIER_AUTHORITY) {
            let sid = format!("S-1-{value}-32");
            let bytes = value.to_be_bytes();

            let parsed = sid.parse::<SidComponents>();

            prop_assert_eq!(
                parsed.as_ref().map(|sid| sid.identifier_authority),
                Ok([bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]])
            );
        }

        #[test]
        fn accepts_hex_identifier_authorities(value in 0u64..=MAX_IDENTIFIER_AUTHORITY) {
            let sid = format!("S-1-0x{value:X}-32");
            let bytes = value.to_be_bytes();

            let parsed = sid.parse::<SidComponents>();

            prop_assert_eq!(
                parsed.as_ref().map(|sid| sid.identifier_authority),
                Ok([bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]])
            );
        }

        #[test]
        fn rejects_identifier_authorities_above_48_bits(value in (MAX_IDENTIFIER_AUTHORITY + 1)..=u64::MAX) {
            let sid = format!("S-1-{value}-32");

            prop_assert_eq!(
                sid.parse::<SidComponents>().err(),
                Some(InvalidSidFormat::IdentifierAuthorityOutOfRange {
                    value,
                    max: MAX_IDENTIFIER_AUTHORITY,
                })
            );
        }

        #[test]
        fn rejects_sub_authorities_above_u32(value in (u64::from(u32::MAX) + 1)..=u64::MAX) {
            let sid = format!("S-1-5-32-{value}");

            prop_assert_eq!(
                sid.parse::<SidComponents>().err(),
                Some(InvalidSidFormat::SubAuthorityOutOfRange {
                    index: 1,
                    value,
                    max: u64::from(u32::MAX),
                })
            );
        }
    }

    #[test]
    fn reports_missing_revision() {
        assert_matches!(
            "S".parse::<SidComponents>(),
            Err(InvalidSidFormat::MissingRevision)
        ));
    }

    #[test]
    fn reports_invalid_revision() {
        assert_eq!(
            "S-not-a-revision-5-32".parse::<SidComponents>(),
            Err(InvalidSidFormat::InvalidRevision)
        );
    }

    #[test]
    fn reports_missing_identifier_authority() {
        assert_matches!(
            "S-1".parse::<SidComponents>(),
            Err(InvalidSidFormat::MissingIdentifierAuthority)
        );
    }

    #[test]
    fn reports_invalid_identifier_authority() {
        assert_matches!(
            "S-1-not-an-authority-32".parse::<SidComponents>(),
            Err(InvalidSidFormat::InvalidIdentifierAuthority)
        ));
        assert_matches!(
            "S-1-0xnothex-32".parse::<SidComponents>(),
            Err(InvalidSidFormat::InvalidIdentifierAuthority)
        ));
    }

    #[test]
    fn rejects_identifier_authority_above_48_bits() {
        assert_matches!(
            "S-1-281474976710656-1".parse::<SidComponents>(),
            Err(InvalidSidFormat::IdentifierAuthorityOutOfRange {
                value: 281_474_976_710_656,
                max: MAX_IDENTIFIER_AUTHORITY,
            })
        ));
        assert_matches!(
            "S-1-0x1000000000000-1".parse::<SidComponents>(),
            Err(InvalidSidFormat::IdentifierAuthorityOutOfRange {
                value: 281_474_976_710_656,
                max: MAX_IDENTIFIER_AUTHORITY,
            })
        ));
    }

    #[test]
    fn reports_missing_sub_authority() {
        assert_matches!(
            "S-1-5".parse::<SidComponents>(),
            Err(InvalidSidFormat::MissingSubAuthority)
        ));
    }

    #[test]
    fn reports_invalid_sub_authority() {
        assert_matches!(
            "S-1-5-not-a-rid".parse::<SidComponents>(),
            Err(InvalidSidFormat::InvalidSubAuthority { index: 0 })
        ));
    }

    #[test]
    fn reports_sub_authority_out_of_range() {
        assert_matches!(
            "S-1-5-4294967296".parse::<SidComponents>(),
            Err(InvalidSidFormat::SubAuthorityOutOfRange {
                index: 0,
                value: 4_294_967_296,
                max: 4_294_967_295,
            })
        ));
    }

    #[test]
    fn reports_invalid_sub_authority_index() {
        assert_matches!(
            "S-1-5-32-not-a-rid".parse::<SidComponents>(),
            Err(InvalidSidFormat::InvalidSubAuthority { index: 1 })
        ));
    }

    #[test]
    fn reports_too_many_sub_authorities() {
        assert_matches!(
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16".parse::<SidComponents>(),
            Err(InvalidSidFormat::TooManySubAuthorities {
                count: 16,
                max: MAX_SUBAUTHORITY_COUNT_USIZE,
            })
        ));
    }
}
