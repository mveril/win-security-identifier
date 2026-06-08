use crate::{ConstSid, Sid, SidClassification};
use core::borrow::Borrow;
use core::fmt::{self, Debug, Display};
use core::ops::Deref;
use core::ptr;

const ACCOUNT_DOMAIN_SID_SUB_AUTHORITY_COUNT: usize = 4;
const ACCOUNT_SID_SUB_AUTHORITY_COUNT: usize = ACCOUNT_DOMAIN_SID_SUB_AUTHORITY_COUNT + 1; // +1 for the RID

/// Borrowed view over a domain account SID (`S-1-5-21-*-*-*-RID`).
///
/// This excludes other SID families whose last sub-authority may still be
/// useful structurally, but is not an account RID for this type.
#[repr(transparent)]
pub struct AccountSid {
    inner: Sid,
}

/// Error returned when a SID is not an account SID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NotAccountSid;

impl AccountSid {
    /// Returns this account SID as a regular [`Sid`].
    #[must_use]
    #[inline]
    pub const fn as_sid(&self) -> &Sid {
        &self.inner
    }

    /// Returns the account RID.
    ///
    /// This accessor is available only after the SID has been validated as a
    /// domain account SID (`S-1-5-21-*-*-*-RID`).
    #[must_use]
    #[inline]
    pub const fn rid(&self) -> u32 {
        self.inner.last_sub_authority()
    }

    /// Returns the account domain SID by value.
    ///
    /// This cannot be returned as a zero-copy `&Sid` because the SID header stores
    /// the sub-authority count, and the domain SID has one fewer sub-authority.
    #[must_use]
    #[inline]
    pub fn account_domain_sid(&self) -> ConstSid<ACCOUNT_DOMAIN_SID_SUB_AUTHORITY_COUNT> {
        let sub_authorities = self.inner.sub_authorities();
        debug_assert!(
            matches!(sub_authorities, [21, _, _, _, _]),
            "AccountSid invariant requires S-1-5-21-*-*-*-RID"
        );
        debug_assert_eq!(
            sub_authorities.len(),
            ACCOUNT_SID_SUB_AUTHORITY_COUNT,
            "AccountSid invariant requires exactly five sub-authorities"
        );

        #[expect(
            clippy::indexing_slicing,
            reason = "AccountSid invariant guarantees exactly five sub-authorities"
        )]
        let domain_sub_authorities = &sub_authorities[..sub_authorities.len() - 1];
        debug_assert_eq!(
            domain_sub_authorities.len(),
            4,
            "dropping the RID from an account SID must leave a four-part domain SID"
        );

        // SAFETY: AccountSid requires exactly five sub-authorities, so dropping
        // the RID leaves the valid four-part domain SID.
        unsafe {
            ConstSid::new(
                self.inner.identifier_authority,
                domain_sub_authorities.try_into().unwrap_unchecked(),
            )
        }
    }

    #[must_use]
    #[inline]
    pub(crate) fn is_account_sid(sid: &Sid) -> bool {
        sid.classification() == SidClassification::AccountDomain && has_account_rid_shape(sid)
    }
}

#[inline]
fn has_account_rid_shape(sid: &Sid) -> bool {
    matches!(sid.sub_authorities(), [21, _, _, _, _])
}

impl<'a> TryFrom<&'a Sid> for &'a AccountSid {
    type Error = NotAccountSid;

    #[inline]
    fn try_from(value: &'a Sid) -> Result<Self, Self::Error> {
        if AccountSid::is_account_sid(value) {
            // SAFETY: AccountSid is repr(transparent) over Sid and the shape was validated above.
            Ok(unsafe { &*(ptr::from_ref(value) as *const AccountSid) })
        } else {
            Err(NotAccountSid)
        }
    }
}

impl AsRef<Sid> for AccountSid {
    #[inline]
    fn as_ref(&self) -> &Sid {
        self.as_sid()
    }
}

impl Borrow<Sid> for AccountSid {
    #[inline]
    fn borrow(&self) -> &Sid {
        self.as_sid()
    }
}

impl Deref for AccountSid {
    type Target = Sid;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_sid()
    }
}

impl<'a> From<&'a AccountSid> for ConstSid<ACCOUNT_SID_SUB_AUTHORITY_COUNT> {
    #[inline]
    fn from(value: &'a AccountSid) -> Self {
        debug_assert!(
            matches!(value.inner.sub_authorities(), [21, _, _, _, _]),
            "AccountSid invariant requires S-1-5-21-*-*-*-RID"
        );
        // SAFETY: AccountSid invariant guarantees the correct shape for the domain SID and RID.
        Self::new(value.inner.identifier_authority, unsafe {
            value.inner.sub_authorities().try_into().unwrap_unchecked()
        })
    }
}

impl Debug for AccountSid {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(self.as_sid(), f)
    }
}

impl Display for AccountSid {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self.as_sid(), f)
    }
}

impl<'a> From<&'a AccountSid> for &'a Sid {
    #[inline]
    fn from(value: &'a AccountSid) -> Self {
        value.as_sid()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Unwrap is not an issue in tests")]
mod tests {
    use super::*;
    use crate::{ConstSid, SidIdentifierAuthority, well_known};
    use proptest::prelude::*;

    #[test]
    fn rejects_builtin_alias_sid() {
        assert!(<&AccountSid>::try_from(well_known::BUILTIN_ADMINISTRATORS.as_sid()).is_err());
    }

    proptest! {
        #[test]
        fn accepts_domain_account_sid(
            domain_part_1 in any::<u32>(),
            domain_part_2 in any::<u32>(),
            domain_part_3 in any::<u32>(),
            rid in any::<u32>(),
        ) {
            let sid = ConstSid::new(
                SidIdentifierAuthority::NT_AUTHORITY,
                [21, domain_part_1, domain_part_2, domain_part_3, rid],
            );

            let account_sid = <&AccountSid>::try_from(sid.as_sid()).unwrap();
            let domain_sid = ConstSid::new(
                SidIdentifierAuthority::NT_AUTHORITY,
                [21, domain_part_1, domain_part_2, domain_part_3],
            );

            prop_assert_eq!(account_sid.rid(), rid);
            prop_assert_eq!(account_sid.account_domain_sid(), domain_sid);
            prop_assert_eq!(account_sid.as_sid(), sid.as_sid());
        }

        #[test]
        fn rejects_domain_sid_without_account_rid(
            domain_part_1 in any::<u32>(),
            domain_part_2 in any::<u32>(),
            domain_part_3 in any::<u32>(),
        ) {
            let sid = ConstSid::new(
                SidIdentifierAuthority::NT_AUTHORITY,
                [21, domain_part_1, domain_part_2, domain_part_3],
            );

            prop_assert!(<&AccountSid>::try_from(sid.as_sid()).is_err());
        }
    }
}
