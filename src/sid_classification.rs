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
    pub const fn classification(&self) -> SidClassification {
        classify(self.identifier_authority, self.sub_authorities())
    }
}

pub const fn classify(
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

const fn classify_null(sub_authorities: &[u32]) -> SidClassification {
    match sub_authorities {
        [0] => SidClassification::Null,
        _ => SidClassification::Unknown,
    }
}

const fn classify_world(sub_authorities: &[u32]) -> SidClassification {
    match sub_authorities {
        [0] => SidClassification::World,
        _ => SidClassification::Unknown,
    }
}

const fn classify_local(sub_authorities: &[u32]) -> SidClassification {
    match sub_authorities {
        [0] => SidClassification::Local,
        _ => SidClassification::Unknown,
    }
}

const fn classify_creator(sub_authorities: &[u32]) -> SidClassification {
    match sub_authorities {
        [0] => SidClassification::CreatorOwner,
        [1] => SidClassification::CreatorGroup,
        _ => SidClassification::Unknown,
    }
}

const fn classify_nt_authority(sub_authorities: &[u32]) -> SidClassification {
    match sub_authorities {
        [21, _, ..] => SidClassification::AccountDomain,
        [32, _, ..] => SidClassification::BuiltinAlias,
        [80, _, ..] => SidClassification::Service,
        _ => SidClassification::NtAuthority,
    }
}

const fn classify_package_authority(sub_authorities: &[u32]) -> SidClassification {
    match sub_authorities {
        [2, _, ..] => SidClassification::AppContainer,
        [3, _, ..] => SidClassification::Capability,
        _ => SidClassification::Package,
    }
}

const fn classify_authentication_authority(sub_authorities: &[u32]) -> SidClassification {
    match sub_authorities {
        [1 | 2, ..] => SidClassification::AuthenticationAuthority,
        _ => SidClassification::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::well_known;
    #[cfg(feature = "std")]
    use proptest::collection::vec as prop_vec;
    #[cfg(feature = "std")]
    use proptest::prelude::*;
    #[cfg(feature = "std")]
    use std::vec;
    #[cfg(feature = "std")]
    use std::vec::Vec;

    #[cfg(feature = "std")]
    fn with_prefix(prefix: u32) -> impl Strategy<Value = Vec<u32>> {
        prop_vec(any::<u32>(), 1..=4).prop_map(move |tail| {
            let mut sub_authorities = vec![prefix];
            sub_authorities.extend(tail);
            sub_authorities
        })
    }

    #[cfg(feature = "std")]
    fn single_except(excluded: &'static [u32]) -> impl Strategy<Value = Vec<u32>> {
        any::<u32>()
            .prop_filter("excluded sub-authority", move |sub_authority| {
                !excluded.contains(sub_authority)
            })
            .prop_map(|sub_authority| vec![sub_authority])
    }

    #[cfg(feature = "std")]
    fn with_first_except(excluded: &'static [u32]) -> impl Strategy<Value = Vec<u32>> {
        (
            any::<u32>().prop_filter("excluded first sub-authority", move |sub_authority| {
                !excluded.contains(sub_authority)
            }),
            prop_vec(any::<u32>(), 1..=4),
        )
            .prop_map(|(first, tail)| {
                let mut sub_authorities = vec![first];
                sub_authorities.extend(tail);
                sub_authorities
            })
    }

    fn assert_classifies(
        authority: SidIdentifierAuthority,
        sub_authorities: &[u32],
        expected: SidClassification,
    ) {
        assert_eq!(classify(authority, sub_authorities), expected);
    }

    fn assert_not_classifies(
        authority: SidIdentifierAuthority,
        sub_authorities: &[u32],
        classification: SidClassification,
    ) {
        assert_ne!(classify(authority, sub_authorities), classification);
    }

    #[test]
    fn classifies_in_const_context() {
        const CLASSIFICATION: SidClassification =
            well_known::BUILTIN_ADMINISTRATORS.classification();

        assert_eq!(CLASSIFICATION, SidClassification::BuiltinAlias);
    }

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

    #[test]
    fn classifies_null_true() {
        assert_classifies(
            SidIdentifierAuthority::NULL_AUTHORITY,
            &[0],
            SidClassification::Null,
        );
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_null_false(sub_authorities in prop_oneof![
            Just(vec![]),
            single_except(&[0]),
            with_prefix(0),
        ]) {
            assert_not_classifies(
                SidIdentifierAuthority::NULL_AUTHORITY,
                &sub_authorities,
                SidClassification::Null,
            );
        }
    }

    #[test]
    fn classifies_world_true() {
        assert_classifies(
            SidIdentifierAuthority::SECURITY_WORLD_AUTHORITY,
            &[0],
            SidClassification::World,
        );
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_world_false(sub_authorities in prop_oneof![
            Just(vec![]),
            single_except(&[0]),
            with_prefix(0),
        ]) {
            assert_not_classifies(
                SidIdentifierAuthority::SECURITY_WORLD_AUTHORITY,
                &sub_authorities,
                SidClassification::World,
            );
        }
    }

    #[test]
    fn classifies_local_true() {
        assert_classifies(
            SidIdentifierAuthority::SECURITY_LOCAL_AUTHORITY,
            &[0],
            SidClassification::Local,
        );
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_local_false(sub_authorities in prop_oneof![
            Just(vec![]),
            single_except(&[0]),
            with_prefix(0),
        ]) {
            assert_not_classifies(
                SidIdentifierAuthority::SECURITY_LOCAL_AUTHORITY,
                &sub_authorities,
                SidClassification::Local,
            );
        }
    }

    #[test]
    fn classifies_creator_owner_true() {
        assert_classifies(
            SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY,
            &[0],
            SidClassification::CreatorOwner,
        );
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_creator_owner_false(sub_authorities in prop_oneof![
            Just(vec![]),
            single_except(&[0]),
            with_prefix(0),
        ]) {
            assert_not_classifies(
                SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY,
                &sub_authorities,
                SidClassification::CreatorOwner,
            );
        }
    }

    #[test]
    fn classifies_creator_group_true() {
        assert_classifies(
            SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY,
            &[1],
            SidClassification::CreatorGroup,
        );
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_creator_group_false(sub_authorities in prop_oneof![
            Just(vec![]),
            single_except(&[1]),
            with_prefix(1),
        ]) {
            assert_not_classifies(
                SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY,
                &sub_authorities,
                SidClassification::CreatorGroup,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn classifies_nt_authority_true(sub_authorities in prop_oneof![
            Just(vec![]),
            Just(vec![21]),
            Just(vec![32]),
            Just(vec![80]),
            single_except(&[21, 32, 80]),
        ]) {
            assert_classifies(
                SidIdentifierAuthority::NT_AUTHORITY,
                &sub_authorities,
                SidClassification::NtAuthority,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_nt_authority_false(
            (authority, sub_authorities) in prop_oneof![
                Just((SidIdentifierAuthority::NULL_AUTHORITY, vec![0])),
                Just((SidIdentifierAuthority::SECURITY_WORLD_AUTHORITY, vec![0])),
                Just((SidIdentifierAuthority::SECURITY_LOCAL_AUTHORITY, vec![0])),
                with_prefix(21).prop_map(|sub_authorities| {
                    (SidIdentifierAuthority::NT_AUTHORITY, sub_authorities)
                }),
                with_prefix(32).prop_map(|sub_authorities| {
                    (SidIdentifierAuthority::NT_AUTHORITY, sub_authorities)
                }),
                with_prefix(80).prop_map(|sub_authorities| {
                    (SidIdentifierAuthority::NT_AUTHORITY, sub_authorities)
                }),
            ]
        ) {
            assert_not_classifies(authority, &sub_authorities, SidClassification::NtAuthority);
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn classifies_account_domain_true(sub_authorities in with_prefix(21)) {
            assert_classifies(
                SidIdentifierAuthority::NT_AUTHORITY,
                &sub_authorities,
                SidClassification::AccountDomain,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_account_domain_false(sub_authorities in prop_oneof![
            Just(vec![]),
            Just(vec![21]),
            with_first_except(&[21]),
        ]) {
            assert_not_classifies(
                SidIdentifierAuthority::NT_AUTHORITY,
                &sub_authorities,
                SidClassification::AccountDomain,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn classifies_builtin_alias_true(sub_authorities in with_prefix(32)) {
            assert_classifies(
                SidIdentifierAuthority::NT_AUTHORITY,
                &sub_authorities,
                SidClassification::BuiltinAlias,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_builtin_alias_false(sub_authorities in prop_oneof![
            Just(vec![]),
            Just(vec![32]),
            with_first_except(&[32]),
        ]) {
            assert_not_classifies(
                SidIdentifierAuthority::NT_AUTHORITY,
                &sub_authorities,
                SidClassification::BuiltinAlias,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn classifies_service_true(sub_authorities in with_prefix(80)) {
            assert_classifies(
                SidIdentifierAuthority::NT_AUTHORITY,
                &sub_authorities,
                SidClassification::Service,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_service_false(sub_authorities in prop_oneof![
            Just(vec![]),
            Just(vec![80]),
            with_first_except(&[80]),
        ]) {
            assert_not_classifies(
                SidIdentifierAuthority::NT_AUTHORITY,
                &sub_authorities,
                SidClassification::Service,
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

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn classifies_integrity_level_true(sub_authorities in prop_vec(any::<u32>(), 1..=4)) {
            assert_classifies(
                SidIdentifierAuthority::MANDATORY_LABEL_AUTHORITY,
                &sub_authorities,
                SidClassification::IntegrityLevel,
            );
        }
    }

    #[test]
    fn does_not_classify_integrity_level_false() {
        assert_not_classifies(
            SidIdentifierAuthority::MANDATORY_LABEL_AUTHORITY,
            &[],
            SidClassification::IntegrityLevel,
        );
        assert_not_classifies(
            SidIdentifierAuthority::NT_AUTHORITY,
            &[8192],
            SidClassification::IntegrityLevel,
        );
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn classifies_package_true(sub_authorities in prop_oneof![
            Just(vec![]),
            Just(vec![2]),
            Just(vec![3]),
            single_except(&[2, 3]),
            with_first_except(&[2, 3]),
        ]) {
            assert_classifies(
                SidIdentifierAuthority::APP_PACKAGE_AUTHORITY,
                &sub_authorities,
                SidClassification::Package,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_package_false(sub_authorities in prop_oneof![
            with_prefix(2),
            with_prefix(3),
        ]) {
            assert_not_classifies(
                SidIdentifierAuthority::APP_PACKAGE_AUTHORITY,
                &sub_authorities,
                SidClassification::Package,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn classifies_app_container_true(sub_authorities in with_prefix(2)) {
            assert_classifies(
                SidIdentifierAuthority::APP_PACKAGE_AUTHORITY,
                &sub_authorities,
                SidClassification::AppContainer,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_app_container_false(sub_authorities in prop_oneof![
            Just(vec![]),
            Just(vec![2]),
            with_first_except(&[2]),
        ]) {
            assert_not_classifies(
                SidIdentifierAuthority::APP_PACKAGE_AUTHORITY,
                &sub_authorities,
                SidClassification::AppContainer,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn classifies_capability_true(sub_authorities in with_prefix(3)) {
            assert_classifies(
                SidIdentifierAuthority::APP_PACKAGE_AUTHORITY,
                &sub_authorities,
                SidClassification::Capability,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_capability_false(sub_authorities in prop_oneof![
            Just(vec![]),
            Just(vec![3]),
            with_first_except(&[3]),
        ]) {
            assert_not_classifies(
                SidIdentifierAuthority::APP_PACKAGE_AUTHORITY,
                &sub_authorities,
                SidClassification::Capability,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn classifies_authentication_authority_true(sub_authorities in prop_oneof![
            Just(vec![1]),
            Just(vec![2]),
            with_prefix(1),
            with_prefix(2),
        ]) {
            assert_classifies(
                SidIdentifierAuthority::SECURITY_AUTHENTICATION_AUTHORITY,
                &sub_authorities,
                SidClassification::AuthenticationAuthority,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_authentication_authority_false(sub_authorities in prop_oneof![
            Just(vec![]),
            with_first_except(&[1, 2]),
        ]) {
            assert_not_classifies(
                SidIdentifierAuthority::SECURITY_AUTHENTICATION_AUTHORITY,
                &sub_authorities,
                SidClassification::AuthenticationAuthority,
            );
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn classifies_unknown_true((authority, sub_authorities) in prop_oneof![
            Just((SidIdentifierAuthority::SECURITY_NON_UNIQUE_AUTHORITY, vec![])),
            Just((SidIdentifierAuthority::SECURITY_NON_UNIQUE_AUTHORITY, vec![0])),
            Just((SidIdentifierAuthority::SECURITY_RESOURCE_MANAGER_AUTHORITY, vec![0])),
            Just((SidIdentifierAuthority::NULL_AUTHORITY, vec![])),
            Just((SidIdentifierAuthority::NULL_AUTHORITY, vec![1])),
            Just((SidIdentifierAuthority::SECURITY_WORLD_AUTHORITY, vec![])),
            Just((SidIdentifierAuthority::SECURITY_LOCAL_AUTHORITY, vec![1])),
            Just((SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY, vec![2])),
            Just((SidIdentifierAuthority::MANDATORY_LABEL_AUTHORITY, vec![])),
            with_first_except(&[1, 2]).prop_map(|sub_authorities| {
                (
                    SidIdentifierAuthority::SECURITY_AUTHENTICATION_AUTHORITY,
                    sub_authorities,
                )
            }),
        ]) {
            assert_classifies(authority, &sub_authorities, SidClassification::Unknown);
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn does_not_classify_unknown_false((authority, sub_authorities) in prop_oneof![
            Just((SidIdentifierAuthority::NULL_AUTHORITY, vec![0])),
            Just((SidIdentifierAuthority::SECURITY_WORLD_AUTHORITY, vec![0])),
            Just((SidIdentifierAuthority::SECURITY_LOCAL_AUTHORITY, vec![0])),
            Just((SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY, vec![0])),
            Just((SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY, vec![1])),
            Just((SidIdentifierAuthority::NT_AUTHORITY, vec![])),
            with_prefix(21).prop_map(|sub_authorities| {
                (SidIdentifierAuthority::NT_AUTHORITY, sub_authorities)
            }),
            with_prefix(32).prop_map(|sub_authorities| {
                (SidIdentifierAuthority::NT_AUTHORITY, sub_authorities)
            }),
            with_prefix(80).prop_map(|sub_authorities| {
                (SidIdentifierAuthority::NT_AUTHORITY, sub_authorities)
            }),
            prop_vec(any::<u32>(), 1..=4).prop_map(|sub_authorities| {
                (
                    SidIdentifierAuthority::MANDATORY_LABEL_AUTHORITY,
                    sub_authorities,
                )
            }),
            Just((SidIdentifierAuthority::APP_PACKAGE_AUTHORITY, vec![])),
            with_prefix(2).prop_map(|sub_authorities| {
                (SidIdentifierAuthority::APP_PACKAGE_AUTHORITY, sub_authorities)
            }),
            with_prefix(3).prop_map(|sub_authorities| {
                (SidIdentifierAuthority::APP_PACKAGE_AUTHORITY, sub_authorities)
            }),
            with_prefix(1).prop_map(|sub_authorities| {
                (
                    SidIdentifierAuthority::SECURITY_AUTHENTICATION_AUTHORITY,
                    sub_authorities,
                )
            }),
        ]) {
            assert_not_classifies(authority, &sub_authorities, SidClassification::Unknown);
        }
    }
}
