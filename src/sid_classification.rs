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

fn classify(authority: SidIdentifierAuthority, sub_authorities: &[u32]) -> SidClassification {
    match authority {
        SidIdentifierAuthority::NULL_AUTHORITY => classify_null(sub_authorities),
        SidIdentifierAuthority::SECURITY_WORLD_AUTHORITY => classify_world(sub_authorities),
        SidIdentifierAuthority::SECURITY_LOCAL_AUTHORITY => classify_local(sub_authorities),
        SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY => classify_creator(sub_authorities),
        SidIdentifierAuthority::NT_AUTHORITY => classify_nt_authority(sub_authorities),
        SidIdentifierAuthority::APP_PACKAGE_AUTHORITY => {
            classify_package_authority(sub_authorities)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConstSid, well_known};

    fn assert_classifies(
        authority: SidIdentifierAuthority,
        sub_authorities: &[u32],
        expected: SidClassification,
    ) {
        assert_eq!(classify(authority, sub_authorities), expected);
    }

    #[test]
    fn classifies_basic_well_known_sids() {
        assert_eq!(
            well_known::NULL.as_sid().classification(),
            SidClassification::Null
        );
        assert_eq!(
            well_known::WORLD.as_sid().classification(),
            SidClassification::World
        );
        assert_eq!(
            well_known::LOCAL.as_sid().classification(),
            SidClassification::Local
        );
        assert_eq!(
            well_known::CREATOR_OWNER.as_sid().classification(),
            SidClassification::CreatorOwner
        );
        assert_eq!(
            well_known::CREATOR_GROUP.as_sid().classification(),
            SidClassification::CreatorGroup
        );
    }

    #[test]
    fn classifies_only_exact_basic_well_known_sids() {
        let cases = [
            (
                SidIdentifierAuthority::NULL_AUTHORITY,
                &[0, 1][..],
                SidClassification::Unknown,
            ),
            (
                SidIdentifierAuthority::SECURITY_WORLD_AUTHORITY,
                &[0, 1][..],
                SidClassification::Unknown,
            ),
            (
                SidIdentifierAuthority::SECURITY_LOCAL_AUTHORITY,
                &[0, 1][..],
                SidClassification::Unknown,
            ),
            (
                SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY,
                &[0, 1][..],
                SidClassification::Unknown,
            ),
            (
                SidIdentifierAuthority::SECURITY_CREATOR_AUTHORITY,
                &[2][..],
                SidClassification::Unknown,
            ),
        ];

        for (authority, sub_authorities, expected) in cases {
            assert_classifies(authority, sub_authorities, expected);
        }
    }

    #[test]
    fn classifies_nt_authority_family_boundaries() {
        let cases = [
            (&[21][..], SidClassification::NtAuthority),
            (&[21, 1][..], SidClassification::AccountDomain),
            (&[21, 1, 2, 3][..], SidClassification::AccountDomain),
            (&[32][..], SidClassification::NtAuthority),
            (&[32, 544][..], SidClassification::BuiltinAlias),
            (&[32, 544, 1][..], SidClassification::BuiltinAlias),
            (&[80][..], SidClassification::NtAuthority),
            (&[80, 1][..], SidClassification::Service),
            (&[80, 1, 2, 3, 4, 5][..], SidClassification::Service),
            (&[18][..], SidClassification::NtAuthority),
            (&[79, 1][..], SidClassification::NtAuthority),
            (&[81, 1][..], SidClassification::NtAuthority),
        ];

        for (sub_authorities, expected) in cases {
            assert_classifies(
                SidIdentifierAuthority::NT_AUTHORITY,
                sub_authorities,
                expected,
            );
        }

        assert_eq!(
            well_known::BUILTIN_ADMINISTRATORS.as_sid().classification(),
            SidClassification::BuiltinAlias
        );
        assert_eq!(
            well_known::LOCAL_SYSTEM.as_sid().classification(),
            SidClassification::NtAuthority
        );
    }

    #[test]
    fn classifies_integrity_and_package_authorities() {
        let integrity = ConstSid::new(SidIdentifierAuthority::MANDATORY_LABEL_AUTHORITY, [8192]);
        let app_container = ConstSid::new(SidIdentifierAuthority::APP_PACKAGE_AUTHORITY, [2, 1]);
        let capability = ConstSid::new(SidIdentifierAuthority::APP_PACKAGE_AUTHORITY, [3, 1]);

        assert_eq!(
            integrity.as_sid().classification(),
            SidClassification::IntegrityLevel
        );
        assert_eq!(
            app_container.as_sid().classification(),
            SidClassification::AppContainer
        );
        assert_eq!(
            capability.as_sid().classification(),
            SidClassification::Capability
        );
    }

    #[test]
    fn classifies_package_authority_family_boundaries() {
        let cases = [
            (&[][..], SidClassification::Package),
            (&[2][..], SidClassification::Package),
            (&[2, 1][..], SidClassification::AppContainer),
            (&[2, 1, 2][..], SidClassification::AppContainer),
            (&[3][..], SidClassification::Package),
            (&[3, 1][..], SidClassification::Capability),
            (&[3, 1, 2][..], SidClassification::Capability),
            (&[1, 1][..], SidClassification::Package),
            (&[4, 1][..], SidClassification::Package),
        ];

        for (sub_authorities, expected) in cases {
            assert_classifies(
                SidIdentifierAuthority::APP_PACKAGE_AUTHORITY,
                sub_authorities,
                expected,
            );
        }
    }

    #[test]
    fn classifies_mandatory_label_authority_boundaries() {
        assert_classifies(
            SidIdentifierAuthority::MANDATORY_LABEL_AUTHORITY,
            &[],
            SidClassification::Unknown,
        );
        assert_classifies(
            SidIdentifierAuthority::MANDATORY_LABEL_AUTHORITY,
            &[8192],
            SidClassification::IntegrityLevel,
        );
        assert_classifies(
            SidIdentifierAuthority::MANDATORY_LABEL_AUTHORITY,
            &[8192, 1],
            SidClassification::IntegrityLevel,
        );
    }
}
