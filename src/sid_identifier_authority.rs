#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Represents the identifier authority in a Security Identifier ([`crate::Sid`]).
pub struct SidIdentifierAuthority {
    /// The raw bytes of the identifier authority.
    pub value: [u8; 6],
}

impl SidIdentifierAuthority {
    /// Null Authority (S-1-0)
    ///
    /// Used to represent a null SID.
    pub const NULL_AUTHORITY: Self = Self::new([0, 0, 0, 0, 0, 0]);

    /// World Authority (S-1-1)
    /// Used to represent the "Everyone" group.
    pub const SECURITY_WORLD_AUTHORITY: Self = Self::new([0, 0, 0, 0, 0, 1]);

    /// Local Authority (S-1-2)
    ///
    /// Used to represent local users.
    pub const SECURITY_LOCAL_AUTHORITY: Self = Self::new([0, 0, 0, 0, 0, 2]);

    /// Creator Authority (S-1-3)
    ///
    /// Used to represent creator owner/group SIDs.
    pub const SECURITY_CREATOR_AUTHORITY: Self = Self::new([0, 0, 0, 0, 0, 3]);

    /// Non-unique Authority (S-1-4)
    ///
    /// Used by non-unique SIDs (not commonly used directly).
    pub const SECURITY_NON_UNIQUE_AUTHORITY: Self = Self::new([0, 0, 0, 0, 0, 4]);

    /// NT Authority (S-1-5)
    ///
    /// The most common authority, under which most Windows well-known SIDs are defined
    /// (e.g. Local System, Administrators, Users, etc.).
    pub const NT_AUTHORITY: Self = Self::new([0, 0, 0, 0, 0, 5]);

    /// Resource Manager Authority (S-1-9)
    ///
    /// Used by Windows resource managers (e.g. for claims-based access control).
    pub const SECURITY_RESOURCE_MANAGER_AUTHORITY: Self = Self::new([0, 0, 0, 0, 0, 9]);

    /// Creates a new `SidIdentifierAuthority` from the raw bytes.
    #[inline]
    #[must_use]
    pub const fn new(value: [u8; 6]) -> Self {
        Self { value }
    }
}

impl Default for SidIdentifierAuthority {
    #[inline]
    fn default() -> Self {
        Self::NULL_AUTHORITY
    }
}

impl From<[u8; 6]> for SidIdentifierAuthority {
    #[inline]
    fn from(value: [u8; 6]) -> Self {
        Self { value }
    }
}

impl From<SidIdentifierAuthority> for [u8; 6] {
    #[inline]
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
