use crate::{Sid, SidIdentifierAuthority};

/// High-level category for a Windows Security Identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SidClassification {
    /// Null SID (`S-1-0-0`).
    Null,
    /// World SID (`S-1-1-0`).
    World,
    /// Local SID (`S-1-2-0`).
    Local,
    /// Creator owner SID (`S-1-3-0`).
    CreatorOwner,
    /// Creator group SID (`S-1-3-1`).
    CreatorGroup,
    /// SID under NT authority (`S-1-5`) with no more specific classification.
    NtAuthority,
    /// Builtin alias SID (`S-1-5-32-*`).
    BuiltinAlias,
    /// Account domain SID family (`S-1-5-21-*`).
    AccountDomain,
    /// Mandatory integrity label SID (`S-1-16-*`).
    IntegrityLevel,
    /// Service SID family (`S-1-5-80-*`).
    Service,
    /// `AppContainer` package SID family (`S-1-15-2-*`).
    AppContainer,
    /// Capability SID family (`S-1-15-3-*`).
    Capability,
    /// Package authority SID under `S-1-15` with no more specific classification.
    Package,
    /// Authentication authority SID family (`S-1-18-*`).
    AuthenticationAuthority,
    /// SID shape not recognized by this crate.
    Unknown,
}

impl Sid {
    /// Returns a high-level classification for this SID.
    #[must_use]
    #[inline]
    pub fn classification(&self) -> SidClassification {
        classify(self.identifier_authority, self.sub_authorities())
    }
}

pub fn classify(
    authority: SidIdentifierAuthority,
    sub_authorities: &[u32],
) -> SidClassification {
    match authority {
        SidIdentifierAuthority::NULL_AUTHORITY => classify_null(sub_authorities),
        SidIdentifierAuthority::SECURITY_WORLD_AUTHORITY => classify_world(sub_authorities),
        SidIdentifierAuthority::SECURITY_LOCAL_AUTHORITY => classify_local(sub_authorities),
        SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY => classify_creator(sub_authorities),
        SidIdentifierAuthority::NT_AUTHORITY => classify_nt_authority(sub_authorities),
        SidIdentifierAuthority::APP_PACKAGE_AUTHORITY => {
            classify_package_authority(sub_authorities)
        }
        SidIdentifierAuthority::SECURITY_AUTHENTICATION_AUTHORITY => {
            classify_authentication_authority(sub_authorities)
        }
        SidIdentifierAuthority::MANDATORY_LABEL_AUTHORITY if !sub_authorities.is_empty() => {
            SidClassification::IntegrityLevel
        }
        _ => SidClassification::Unknown,
    }
}

fn classify_null(sub_authorities: &[u32]) -> SidClassification {
    if sub_authorities == [0] {
        SidClassification::Null
    } else {
        SidClassification::Unknown
    }
}

fn classify_world(sub_authorities: &[u32]) -> SidClassification {
    if sub_authorities == [0] {
        SidClassification::World
    } else {
        SidClassification::Unknown
    }
}

fn classify_local(sub_authorities: &[u32]) -> SidClassification {
    if sub_authorities == [0] {
        SidClassification::Local
    } else {
        SidClassification::Unknown
    }
}

fn classify_creator(sub_authorities: &[u32]) -> SidClassification {
    match sub_authorities {
        [0] => SidClassification::CreatorOwner,
        [1] => SidClassification::CreatorGroup,
        _ => SidClassification::Unknown,
    }
}

fn classify_nt_authority(sub_authorities: &[u32]) -> SidClassification {
    match sub_authorities {
        [21, _, ..] => SidClassification::AccountDomain,
        [32, _, ..] => SidClassification::BuiltinAlias,
        [80, _, ..] => SidClassification::Service,
        _ => SidClassification::NtAuthority,
    }
}

fn classify_package_authority(sub_authorities: &[u32]) -> SidClassification {
    match sub_authorities {
        [2, _, ..] => SidClassification::AppContainer,
        [3, _, ..] => SidClassification::Capability,
        _ => SidClassification::Package,
    }
}

fn classify_authentication_authority(sub_authorities: &[u32]) -> SidClassification {
    match sub_authorities {
        [1 | 2, ..] => SidClassification::AuthenticationAuthority,
        _ => SidClassification::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::well_known;
    use proptest::prelude::*;

    #[test]
    fn classifies_basic_well_known_sids() {
        assert_eq!(well_known::NULL.classification(), SidClassification::Null);
        assert_eq!(well_known::WORLD.classification(), SidClassification::World);
        assert_eq!(well_known::LOCAL.classification(), SidClassification::Local);
        assert_eq!(
            well_known::CREATOR_OWNER.classification(),
            SidClassification::CreatorOwner
        );
        assert_eq!(
            well_known::CREATOR_GROUP.classification(),
            SidClassification::CreatorGroup
        );
    }

    proptest! {
        #[test]
        fn classifies_only_exact_basic_well_known_sids(
            sub_authorities in prop_oneof![
                Just(vec![0, 1]),
                Just(vec![2]),
            ]
        ) {
            prop_assert_eq!(
                classify(SidIdentifierAuthority::NULL_AUTHORITY, &sub_authorities),
                SidClassification::Unknown
            );
            prop_assert_eq!(
                classify(SidIdentifierAuthority::SECURITY_WORLD_AUTHORITY, &sub_authorities),
                SidClassification::Unknown
            );
            prop_assert_eq!(
                classify(SidIdentifierAuthority::SECURITY_LOCAL_AUTHORITY, &sub_authorities),
                SidClassification::Unknown
            );
            prop_assert_eq!(
                classify(SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY, &sub_authorities),
                SidClassification::Unknown
            );
        }
    }

    proptest! {
        #[test]
        fn classifies_nt_authority_family_boundaries(
            sub_authorities in prop_oneof![
                Just(vec![21]),
                Just(vec![21, 1, 2, 3]),
                Just(vec![32]),
                Just(vec![32, 544]),
                Just(vec![32, 544, 1]),
                Just(vec![80]),
                Just(vec![80, 1]),
                Just(vec![80, 1, 2, 3, 4, 5]),
                Just(vec![18]),
                Just(vec![79, 1]),
                Just(vec![81, 1]),
            ]
        ) {
            let expected = match sub_authorities.as_slice() {
                [21] => SidClassification::NtAuthority,
                [21, _, ..] => SidClassification::AccountDomain,
                [32] => SidClassification::NtAuthority,
                [32, _, ..] => SidClassification::BuiltinAlias,
                [80] => SidClassification::NtAuthority,
                [80, _, ..] => SidClassification::Service,
                [18] => SidClassification::NtAuthority,
                [79, ..] | [81, ..] => SidClassification::NtAuthority,
                _ => unreachable!(),
            };

            prop_assert_eq!(
                classify(SidIdentifierAuthority::NT_AUTHORITY, &sub_authorities),
                expected
            );
        }
    }

    #[test]
    fn classifies_nt_authority_examples_from_well_known_sids() {
        assert_eq!(
            well_known::BUILTIN_ADMINISTRATORS.classification(),
            SidClassification::BuiltinAlias
        );
        assert_eq!(
            well_known::LOCAL_SYSTEM.classification(),
            SidClassification::NtAuthority
        );
    }

    proptest! {
        #[test]
        fn classifies_integrity_and_package_authorities(
            sub_authorities in prop_oneof![
                Just(vec![8192]),
                Just(vec![8192, 1]),
                Just(vec![2, 1]),
                Just(vec![2, 1, 2]),
                Just(vec![3, 1]),
                Just(vec![3, 1, 2]),
            ]
        ) {
            let (authority, expected) = match sub_authorities.as_slice() {
                [8192] | [8192, ..] => (
                    SidIdentifierAuthority::MANDATORY_LABEL_AUTHORITY,
                    SidClassification::IntegrityLevel,
                ),
                [2, 1] | [2, 1, ..] => (
                    SidIdentifierAuthority::APP_PACKAGE_AUTHORITY,
                    SidClassification::AppContainer,
                ),
                [3, 1] | [3, 1, ..] => (
                    SidIdentifierAuthority::APP_PACKAGE_AUTHORITY,
                    SidClassification::Capability,
                ),
                _ => unreachable!(),
            };

            prop_assert_eq!(classify(authority, &sub_authorities), expected);
        }
    }

    proptest! {
        #[test]
        fn classifies_package_authority_family_boundaries(
            sub_authorities in prop_oneof![
                Just(vec![]),
                Just(vec![2]),
                Just(vec![2, 1]),
                Just(vec![2, 1, 2]),
                Just(vec![3]),
                Just(vec![3, 1]),
                Just(vec![3, 1, 2]),
                Just(vec![1, 1]),
                Just(vec![4, 1]),
            ]
        ) {
            let expected = match sub_authorities.as_slice() {
                [2] | [3] => SidClassification::Package,
                [2, 1, ..] => SidClassification::AppContainer,
                [3, 1, ..] => SidClassification::Capability,
                [] | [1, 1] | [4, 1] => SidClassification::Package,
                _ => unreachable!(),
            };

            prop_assert_eq!(
                classify(SidIdentifierAuthority::APP_PACKAGE_AUTHORITY, &sub_authorities),
                expected
            );
        }
    }

    proptest! {
        #[test]
        fn classifies_mandatory_label_authority_boundaries(
            sub_authorities in prop_oneof![
                Just(vec![]),
                Just(vec![8192]),
                Just(vec![8192, 1]),
            ]
        ) {
            let expected = match sub_authorities.as_slice() {
                [] => SidClassification::Unknown,
                [8192, ..] => SidClassification::IntegrityLevel,
                _ => unreachable!(),
            };

            prop_assert_eq!(
                classify(SidIdentifierAuthority::MANDATORY_LABEL_AUTHORITY, &sub_authorities),
                expected
            );
        }
    }

    proptest! {
        #[test]
        fn classifies_authentication_authority_boundaries(
            sub_authorities in prop_oneof![
                Just(vec![]),
                Just(vec![1]),
                Just(vec![1, 1]),
                Just(vec![2]),
                Just(vec![2, 1]),
                Just(vec![3]),
            ]
        ) {
            let expected = match sub_authorities.as_slice() {
                [1, ..] | [2, ..] => SidClassification::AuthenticationAuthority,
                _ => SidClassification::Unknown,
            };

            prop_assert_eq!(
                classify(SidIdentifierAuthority::SECURITY_AUTHENTICATION_AUTHORITY, &sub_authorities),
                expected
            );
        }
    }
}
