use crate::{Sid, SidClassification, SidIdentifierAuthority, StackSid};
use core::borrow::Borrow;
use core::fmt::{self, Debug, Display};
use core::ops::Deref;

/// Borrowed view over an account SID (`S-1-5-21-*-*-*-RID`).
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
    #[must_use]
    #[inline]
    pub const fn rid(&self) -> u32 {
        self.inner.rid()
    }

    /// Returns the account domain SID by value.
    ///
    /// This cannot be returned as a zero-copy `&Sid` because the SID header stores
    /// the sub-authority count, and the domain SID has one fewer sub-authority.
    #[must_use]
    #[inline]
    pub fn account_domain_sid(&self) -> StackSid {
        let sub_authorities = self.inner.sub_authorities();
        #[expect(
            clippy::indexing_slicing,
            reason = "AccountSid invariant guarantees at least one RID sub-authority"
        )]
        // SAFETY: AccountSid requires exactly five sub-authorities, so dropping
        // the RID leaves the valid four-part domain SID.
        unsafe {
            StackSid::new_unchecked(
                self.inner.identifier_authority,
                &sub_authorities[..sub_authorities.len() - 1],
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
            Ok(unsafe { &*(core::ptr::from_ref(value) as *const Sid as *const AccountSid) })
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
    use crate::{ConstSid, well_known};

    #[test]
    fn accepts_domain_account_sid() {
        let sid = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [21, 1, 2, 3, 500]);

        let account_sid = <&AccountSid>::try_from(sid.as_sid()).unwrap();
        let domain_sid = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [21, 1, 2, 3]);

        assert_eq!(account_sid.rid(), 500);
        assert_eq!(account_sid.account_domain_sid(), domain_sid);
        assert_eq!(account_sid.as_sid(), sid.as_sid());
    }

    #[test]
    fn rejects_builtin_alias_sid() {
        assert!(<&AccountSid>::try_from(well_known::BUILTIN_ADMINISTRATORS.as_sid()).is_err());
    }

    #[test]
    fn rejects_domain_sid_without_account_rid() {
        let sid = ConstSid::new(SidIdentifierAuthority::NT_AUTHORITY, [21, 1, 2, 3]);

        assert!(<&AccountSid>::try_from(sid.as_sid()).is_err());
    }
}
