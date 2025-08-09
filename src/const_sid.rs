#[cfg(not(has_ptr_metadata))]
use crate::polyfils_ptr::from_raw_parts;
use crate::{SecurityIdentifier, Sid, SidIdentifierAuthority, utils::sub_authority_size_guard};
#[cfg(has_ptr_metadata)]
use std::ptr::from_raw_parts;
use std::{
    array::TryFromSliceError,
    ffi::c_void,
    fmt::{self, Display},
    hash::{self, Hash},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ConstSid<const N: usize> {
    pub revision: u8,
    sub_authority_count: u8,
    pub identifier_authority: SidIdentifierAuthority,
    pub sub_authority: [u32; N],
}

impl<const N: usize> AsRef<Sid> for ConstSid<N> {
    fn as_ref(&self) -> &Sid {
        unsafe { &*from_raw_parts(self as *const Self as *mut Self as *mut c_void, N) }
    }
}

impl<const N: usize> ConstSid<N> {
    pub const fn new(
        revision: u8,
        identifier_authority: SidIdentifierAuthority,
        sub_authority: [u32; N],
    ) -> Option<Self> {
        if sub_authority_size_guard(N) {
            Some(Self {
                revision,
                sub_authority_count: N as u8,
                sub_authority,
                identifier_authority,
            })
        } else {
            None
        }
    }

    pub fn new_unchecked(
        revision: u8,
        identifier_authority: SidIdentifierAuthority,
        sub_authority: [u32; N],
    ) -> Self {
        Self::new(revision, identifier_authority, sub_authority).unwrap()
    }
}

impl<const N: usize> From<ConstSid<N>> for SecurityIdentifier {
    fn from(value: ConstSid<N>) -> Self {
        let sid: &Sid = value.as_ref();
        sid.to_owned()
    }
}

impl<const N: usize> TryFrom<&Sid> for ConstSid<N> {
    type Error = TryFromSliceError;

    fn try_from(value: &Sid) -> Result<Self, Self::Error> {
        let revision = value.revision;
        let identifier_authority = value.identifier_authority;
        let sub_authority: [u32; N] = value.get_sub_authorities().try_into()?;
        Ok(Self::new_unchecked(
            revision,
            identifier_authority,
            sub_authority,
        ))
    }
}

impl<const N: usize> Display for ConstSid<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sid: &Sid = self.as_ref();
        Display::fmt(sid, f)
    }
}

impl<const N: usize> PartialEq<Sid> for ConstSid<N> {
    fn eq(&self, other: &Sid) -> bool {
        self.as_ref().eq(other)
    }
}

impl<const N: usize> Hash for ConstSid<N> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.revision.hash(state);
        self.sub_authority_count.hash(state);
        self.identifier_authority.hash(state);
        Hash::hash_slice(&self.sub_authority[..], state);
    }
}

#[cfg(test)]
mod test {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use super::*;
    use crate::SidSizeInfo;

    #[test]
    pub fn test_hash() {
        let sid = ConstSid::new(1, [1, 0, 0, 0, 0, 0].into(), [0; 1]).unwrap();
        let mut hasher1 = DefaultHasher::default();
        let mut hasher2 = DefaultHasher::default();
        sid.hash(&mut hasher1);
        sid.as_ref().hash(&mut hasher2);
        assert_eq!(hasher1.finish(), hasher2.finish())
    }

    #[test]
    fn test_layout_matches_sid() {
        use std::alloc::Layout;
        let size = SidSizeInfo {
            sub_authority_count: 1,
        };
        let layout = size.get_layout();
        assert_eq!(Layout::new::<ConstSid<1>>(), layout)
    }
}
