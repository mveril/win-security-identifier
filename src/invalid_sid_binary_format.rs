use thiserror::Error;

/// Error returned when a raw SID byte slice is not a valid Windows SID binary layout.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InvalidSidBinaryFormat {
    #[error("SID binary length {len} is shorter than minimum {min_len}")]
    TooShort { len: usize, min_len: usize },
    #[error("SID binary revision {revision} is invalid, expected {expected}")]
    InvalidRevision { revision: u8, expected: u8 },
    #[error("SID binary sub-authority count {count} is outside {min}..={max}")]
    InvalidSubAuthorityCount { count: u8, min: u8, max: u8 },
    #[error(
        "SID binary length {len} does not match expected length {expected_len} for {count} sub-authorities"
    )]
    InvalidLength {
        len: usize,
        expected_len: usize,
        count: u8,
    },
}
