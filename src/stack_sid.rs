#[cfg(not(has_ptr_metadata))]
use crate::polyfils_ptr::from_raw_parts;
use crate::sid::MAX_SUBAUTHORITY_COUNT;
use crate::utils::sub_authority_size_guard;
use crate::{Sid, SidIdentifierAuthority};
use core::mem::MaybeUninit;
use core::ptr::copy_nonoverlapping;
#[cfg(has_ptr_metadata)]
use core::ptr::from_raw_parts;
use core::str::FromStr;
use delegate::delegate;
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
    pub const fn try_new(
        revision: u8,
        identifier_authority: SidIdentifierAuthority,
        sub_authority: &[u32],
    ) -> Option<Self> {
        if sub_authority_size_guard(sub_authority.len()) {
            let mut array: [MaybeUninit<u32>; MAX_SUBAUTHORITY_COUNT as usize] =
                [MaybeUninit::uninit(); _];
            let array_ptr = array.as_mut_ptr() as *mut u32;
            unsafe {
                copy_nonoverlapping(
                    sub_authority.as_ptr(),
                    array_ptr,
                    sub_authority.len(),
                );
            };
            Some(Self {
                revision,
                sub_authority_count: sub_authority.len() as u8,
                identifier_authority,
                sub_authority: array,
            })
        } else {
            None
        }
    }

    /// Creates a new `SecurityIdentifier` from parts **without validation**.
    ///
    /// # Safety
    /// - Caller must ensure `sub_authority` length is in `1..=15`.
    /// - `identifier_authority` must be a valid Windows authority.
    ///
    /// Violating these preconditions results in undefined behavior or later panics.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, SidIdentifierAuthority};
    /// let sid = unsafe {
    ///     SecurityIdentifier::new_unchecked(
    ///         1,
    ///         SidIdentifierAuthority::NT_AUTHORITY,
    ///         [32u32, 544u32],
    ///     )
    /// };
    /// assert_eq!(sid.revision, 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.get_sub_authorities(), [32u32, 544u32]);
    /// ```
    pub const unsafe fn new_unchecked(
        revision: u8,
        identifier_authority: SidIdentifierAuthority,
        sub_authority: &[u32],
    ) -> Self {
        unsafe { Self::try_new(revision, identifier_authority, sub_authority).unwrap_unchecked() }
    }

    /// Returns a reference to this `StackSid` as a dynamically-sized [`Sid`].
    ///
    /// This allows stack allocated `StackSid` as a regular `Sid`
    /// with a trailing slice of sub-authorities.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{StackSid, SidIdentifierAuthority, Sid};
    /// const ADMIN: StackSid = StackSid::try_new(
    ///     1,
    ///     SidIdentifierAuthority::NT_AUTHORITY,
    ///     &[32, 544],
    /// ).unwrap();
    /// let sid: &Sid = ADMIN.as_sid();
    /// assert_eq!(sid.to_string(), "S-1-5-32-544");
    /// ```
    pub const fn as_sid(&self) -> &Sid {
        // SAFETY: We construct a fat pointer to `Sid` with metadata `N` that
        // matches `sub_authority.len()`. The header layout is compatible
        // (`repr(C)`), and the trailing slice length equals N.
        unsafe {
            &*from_raw_parts(
                self as *const Self as *mut Self as *mut (),
                self.sub_authority_count as usize,
            )
        }
    }

    delegate! {
        to self.as_sid() {
            pub const fn get_sub_authorities(&self) -> &[u32];
        }
    }
}

impl FromStr for StackSid {
    type Err = parsing::InvalidSidFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parsing::SidComponents::from_str(s).map(|cmp| {
            debug_assert_eq!(
                MAX_SUBAUTHORITY_COUNT as usize,
                cmp.sub_authority.capacity()
            );
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
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_sid())
    }
}
