#[cfg(not(has_ptr_metadata))]
use crate::polyfils_ptr::{from_raw_parts, from_raw_parts_mut};
use core::hash::Hash;
#[cfg(has_ptr_metadata)]
use core::ptr::{from_raw_parts, from_raw_parts_mut};

use crate::sid::MAX_SUBAUTHORITY_COUNT;
use crate::utils::sub_authority_size_guard;
use crate::{Sid, SidIdentifierAuthority};
use core::mem::MaybeUninit;
use core::ptr::copy_nonoverlapping;
use core::str::FromStr;
use delegate::delegate;
use parsing;
use std::fmt::Display;

#[repr(C)]
#[derive(Debug)]
pub struct StackSid {
    /// The SID revision value, generally 1.
    pub revision: u8,
    pub(crate) sub_authority_count: u8,
    /// The SID identifier authority value.
    pub identifier_authority: SidIdentifierAuthority,
    /// The SID sub-authority values.
    sub_authority: [MaybeUninit<u32>; MAX_SUBAUTHORITY_COUNT as usize],
}

impl StackSid {
    /// Owned, stack-allocated Windows **Security Identifier** (SID).
    ///
    /// It can be constructed from raw parts, parsed from text, cloned,
    /// or retrieved from the current user's access token (Windows-only).
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{StackSid, SidIdentifierAuthority};
    /// // Build a SID S-1-5-32-544 (Builtin\Administrators) from parts:
    /// let revision = 1u8;
    /// let ia = SidIdentifierAuthority::NT_AUTHORITY; // example ctor
    /// let subs = [32u32, 544u32];
    /// let sid = StackSid::try_new(revision, ia, &subs)
    ///     .expect("valid SID parts");
    /// assert_eq!(sid.revision, 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.get_sub_authorities(), [32u32, 544u32]);
    /// ```
    #[must_use]
    #[inline]
    pub const fn try_new(
        revision: u8,
        identifier_authority: SidIdentifierAuthority,
        sub_authority: &[u32],
    ) -> Option<Self> {
        if sub_authority_size_guard(sub_authority.len()) {
            // Safety: We checked the subauthority length to be in 1..=15.
            unsafe {
                Some(Self::new_unchecked(
                    revision,
                    identifier_authority,
                    sub_authority,
                ))
            }
        } else {
            None
        }
    }

    /// Creates a new `StackSid` from parts **without validation**.
    ///
    /// # Safety
    /// - Caller must ensure `sub_authority` length is in `1..=15`.
    /// - `identifier_authority` must be a valid Windows authority.
    ///
    /// Violating these preconditions results in undefined behavior or later panics.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{StackSid, SidIdentifierAuthority};
    /// let sid = unsafe{StackSid::new_unchecked(
    ///         1,
    ///         SidIdentifierAuthority::NT_AUTHORITY,
    ///         &[32u32, 544u32],
    ///     )};
    /// assert_eq!(sid.revision, 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.get_sub_authorities(), [32u32, 544u32]);
    /// ```
    #[must_use]
    #[inline]
    pub const unsafe fn new_unchecked(
        revision: u8,
        identifier_authority: SidIdentifierAuthority,
        sub_authority: &[u32],
    ) -> Self {
        // initialize array of MaybeUninit
        let mut array = [MaybeUninit::uninit(); MAX_SUBAUTHORITY_COUNT as usize];

        // copy values into the array
        let array_ptr: *mut u32 = array.as_mut_ptr().cast();
        // Safety: We already check the length of sub_authority to be in 1..=15.
        unsafe {
            copy_nonoverlapping(sub_authority.as_ptr(), array_ptr, sub_authority.len());
        }

        Self {
            revision,
            #[expect(
                clippy::cast_possible_truncation,
                reason = "truncation already checked before"
            )]
            sub_authority_count: sub_authority.len() as u8,
            identifier_authority,
            sub_authority: array,
        }
    }

    /// Returns a reference to this `StackSid` as a dynamically-sized [`Sid`].
    ///
    /// This allows a stack allocated `StackSid` to be used as a regular `Sid`
    /// with a trailing slice of sub-authorities.
    #[inline]
    #[must_use]
    pub const fn as_sid(&self) -> &Sid {
        let raw: *const () = std::ptr::from_ref(self).cast();
        // SAFETY: Construct a fat pointer to `Sid` with metadata `N` that
        // matches `sub_authority_count`. The header layout is compatible
        // (`repr(C)`), and the trailing slice length equals `sub_authority_count`.
        unsafe { &*from_raw_parts(raw, self.sub_authority_count as usize) }
    }

    /// Returns a mutable reference to this `StackSid` as a dynamically-sized [`Sid`].
    ///
    /// This allows treating the fixed-size `StackSid` as a regular `Sid`
    /// with a trailing slice of sub-authorities.
    #[inline]
    pub fn as_sid_mut(&mut self) -> &mut Sid {
        let raw: *mut () = std::ptr::from_mut(self).cast();
        // SAFETY: same justification as `as_sid`, but for a mutable reference.
        unsafe { &mut *from_raw_parts_mut(raw, self.sub_authority_count as usize) }
    }

    delegate! {
        to self.as_sid() {
            #[must_use]
            pub const fn get_sub_authorities(&self) -> &[u32];
        }
    }

    delegate! {
        to self.as_sid_mut() {
            pub fn get_sub_authorities_mut(&mut self) -> &mut [u32];
        }
    }
}

impl FromStr for StackSid {
    type Err = parsing::InvalidSidFormat;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parsing::SidComponents::from_str(s).map(|cmp| {
            debug_assert_eq!(
                MAX_SUBAUTHORITY_COUNT as usize,
                cmp.sub_authority.capacity(),
                "Verify sub_autority capacity is same as MAX_SUBAUTHORITY_COUNT"
            );
            // SAFETY: All check are done by SidComponents and the debug assertion.
            unsafe {
                Self::new_unchecked(
                    cmp.revision,
                    SidIdentifierAuthority::new(cmp.identifier_authority),
                    cmp.sub_authority.as_slice(),
                )
            }
        })
    }
}

impl Display for StackSid {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_sid())
    }
}

impl PartialEq for StackSid {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_sid().eq(other.as_sid())
    }
}

impl Hash for StackSid {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_sid().hash(state);
    }
}

impl PartialEq<Sid> for StackSid {
    #[inline]
    fn eq(&self, other: &Sid) -> bool {
        self.as_sid().eq(other)
    }
}

impl PartialEq<StackSid> for Sid {
    #[inline]
    fn eq(&self, other: &StackSid) -> bool {
        self.eq(other.as_sid())
    }
}
