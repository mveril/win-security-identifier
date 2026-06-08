use thiserror::Error;

/// Error returned when SID parts cannot form a valid SID.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InvalidSidParts {
    /// A SID must have at least one sub-authority.
    #[error("SID must contain at least one sub-authority")]
    MissingSubAuthority,
    /// A SID has more sub-authorities than Windows supports.
    #[error("SID has {count} sub-authorities, more than maximum {max}")]
    TooManySubAuthorities { count: usize, max: usize },
}

impl InvalidSidParts {
    pub(crate) const MAX_SUB_AUTHORITIES: usize = parsing::MAX_SUBAUTHORITY_COUNT as usize;

    #[inline]
    pub(crate) const fn validate_len(len: usize) -> Result<(), Self> {
        if len == 0 {
            Err(Self::MissingSubAuthority)
        } else if len > Self::MAX_SUB_AUTHORITIES {
            Err(Self::TooManySubAuthorities {
                count: len,
                max: Self::MAX_SUB_AUTHORITIES,
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InvalidSidParts;

    #[test]
    fn validates_sub_authority_count() {
        assert_eq!(
            InvalidSidParts::validate_len(0),
            Err(InvalidSidParts::MissingSubAuthority)
        );
        assert_eq!(InvalidSidParts::validate_len(1), Ok(()));
        assert_eq!(InvalidSidParts::validate_len(15), Ok(()));
        assert_eq!(
            InvalidSidParts::validate_len(16),
            Err(InvalidSidParts::TooManySubAuthorities { count: 16, max: 15 })
        );
    }
}
