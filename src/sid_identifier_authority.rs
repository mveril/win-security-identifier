#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Represents the identifier authority in a Security Identifier ([crate::Sid]).
pub struct SidIdentifierAuthority {
    /// The raw bytes of the identifier authority.
    pub value: [u8; 6],
}

impl SidIdentifierAuthority {
    /// Creates a new `SidIdentifierAuthority` from the raw bytes.
    pub const fn new(value: [u8; 6]) -> Self {
        Self { value }
    }

    /// Returns the NT authority identifier.
    pub const fn nt_authority() -> Self {
        Self::new([0, 0, 0, 0, 0, 5])
    }

    /// Returns the world authority identifier
    pub const fn world() -> Self {
        Self::new([0, 0, 0, 0, 0, 1])
    }
}

impl Default for SidIdentifierAuthority {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

impl From<[u8; 6]> for SidIdentifierAuthority {
    fn from(value: [u8; 6]) -> Self {
        Self { value }
    }
}

impl From<SidIdentifierAuthority> for [u8; 6] {
    fn from(value: SidIdentifierAuthority) -> Self {
        value.value
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use proptest::prelude::*;
    prop_compose! {
        pub fn arb_identifier_authority()
            (val in 1u8..=5)
            -> SidIdentifierAuthority {
            let mut bytes = [0u8; 6];
            bytes[5] = val;
            SidIdentifierAuthority::from(bytes)
        }
    }
}
