#[cfg(feature = "alloc")]
use crate::SecurityIdentifier;
use crate::internal::SidLenValid;
#[cfg(not(has_ptr_metadata))]
use crate::polyfills_ptr::{from_raw_parts, from_raw_parts_mut};
use core::borrow::{Borrow, BorrowMut};
use core::hash::Hash;
#[cfg(has_ptr_metadata)]
use core::ptr::{from_raw_parts, from_raw_parts_mut};

use crate::sid::MAX_SUBAUTHORITY_COUNT;
use crate::sid_mutation::MAX_SUB_AUTHORITIES;
use crate::utils::{self, validate_sid_bytes_unaligned};
use crate::{ConstSid, InvalidSidBinaryFormat, InvalidSidParts, Sid, SidIdentifierAuthority};
use crate::{
    ExtendSubAuthoritiesError, PopSubAuthoritiesError, PopSubAuthorityError, PoppedSubAuthorities,
    PushSubAuthorityError, TruncateSubAuthoritiesError,
};
use core::fmt::{self, Display};
use core::mem::{MaybeUninit, size_of, size_of_val};
use core::num::NonZeroUsize;
use core::ptr;
use core::str::FromStr;
use delegate::delegate;

#[repr(C)]
pub struct StackSid {
    /// The SID revision value, (currently only 1 is supported).
    pub revision: u8,
    pub(crate) sub_authority_count: u8,
    /// The SID identifier authority value.
    pub identifier_authority: SidIdentifierAuthority,
    /// The SID sub authority values.
    sub_authorities: [MaybeUninit<u32>; MAX_SUBAUTHORITY_COUNT as usize],
}

impl StackSid {
    /// Changes the SID identifier authority without changing its layout.
    #[inline]
    pub const fn set_identifier_authority(&mut self, authority: SidIdentifierAuthority) {
        self.identifier_authority = authority;
    }

    /// Returns mutable access to the existing sub-authorities.
    #[inline]
    pub const fn sub_authorities_mut(&mut self) -> &mut [u32] {
        self.as_sid_mut().sub_authorities_mut()
    }

    /// Appends one sub-authority to the fixed-capacity stack storage.
    ///
    /// # Errors
    /// Returns [`PushSubAuthorityError`] if the SID already has 15 sub-authorities.
    #[inline]
    pub fn try_push_sub_authority(&mut self, value: u32) -> Result<(), PushSubAuthorityError> {
        let current = self.sub_authority_count as usize;
        let max = crate::sid_mutation::max_sub_authorities();
        if current == max {
            return Err(PushSubAuthorityError::MaximumSubAuthoritiesReached { max });
        }
        let Some(slot) = self.sub_authorities.get_mut(current) else {
            return Err(PushSubAuthorityError::MaximumSubAuthoritiesReached { max });
        };
        slot.write(value);
        self.sub_authority_count += 1;
        Ok(())
    }

    /// Collects and appends an iterator without heap allocation.
    ///
    /// The SID is left unchanged if the iterator exceeds the available capacity.
    ///
    /// # Errors
    /// Returns [`ExtendSubAuthoritiesError`] if the iterator would exceed 15 values.
    #[inline]
    pub fn try_extend_sub_authorities<I>(
        &mut self,
        values: I,
    ) -> Result<(), ExtendSubAuthoritiesError>
    where
        I: IntoIterator<Item = u32>,
    {
        let current = self.sub_authority_count as usize;
        let max: usize = crate::sid_mutation::max_sub_authorities();
        let mut pending = arrayvec::ArrayVec::<u32, MAX_SUB_AUTHORITIES>::new();
        for value in values {
            if current + pending.len() == max || pending.try_push(value).is_err() {
                return Err(ExtendSubAuthoritiesError::TooManySubAuthorities { current, max });
            }
        }
        let pending_len = pending.len();
        for (slot, value) in self.sub_authorities.iter_mut().skip(current).zip(pending) {
            slot.write(value);
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the resulting count is validated against the Windows maximum"
        )]
        {
            self.sub_authority_count = (current + pending_len) as u8;
        }
        Ok(())
    }

    /// Removes and returns the final sub-authority.
    ///
    /// # Errors
    /// Returns [`PopSubAuthorityError`] if removing the value would empty the SID.
    #[inline]
    pub fn try_pop_sub_authority(&mut self) -> Result<u32, PopSubAuthorityError> {
        let current = self.sub_authority_count as usize;
        if current == 1 {
            return Err(PopSubAuthorityError::CannotRemoveLastSubAuthority);
        }
        let Some(slot) = self.sub_authorities.get(current - 1) else {
            return Err(PopSubAuthorityError::CannotRemoveLastSubAuthority);
        };
        // SAFETY: every slot below `sub_authority_count` is initialized.
        let value = unsafe { slot.assume_init_read() };
        self.sub_authority_count -= 1;
        Ok(value)
    }

    /// Removes several trailing sub-authorities and returns them in original order.
    ///
    /// # Errors
    /// Returns [`PopSubAuthoritiesError`] if `count` would empty the SID.
    #[inline]
    pub fn try_pop_sub_authorities(
        &mut self,
        count: usize,
    ) -> Result<PoppedSubAuthorities, PopSubAuthoritiesError> {
        let current = self.sub_authority_count as usize;
        let available = current - 1;
        if count > available {
            return Err(PopSubAuthoritiesError::InsufficientSubAuthorities {
                requested: count,
                available,
            });
        }
        let new_count = current - count;
        let Some(tail) = self.sub_authorities().get(new_count..) else {
            return Err(PopSubAuthoritiesError::InsufficientSubAuthorities {
                requested: count,
                available,
            });
        };
        let Some(removed) = PoppedSubAuthorities::try_from_slice(tail) else {
            return Err(PopSubAuthoritiesError::InsufficientSubAuthorities {
                requested: count,
                available,
            });
        };
        #[expect(
            clippy::cast_possible_truncation,
            reason = "new_count is no larger than the existing valid u8 count"
        )]
        {
            self.sub_authority_count = new_count as u8;
        }
        Ok(removed)
    }

    /// Truncates trailing sub-authorities while retaining at least one value.
    ///
    /// # Errors
    /// Returns [`TruncateSubAuthoritiesError`] when `new_len` is zero.
    #[inline]
    pub const fn try_truncate_sub_authorities(
        &mut self,
        new_len: NonZeroUsize,
    ) -> Result<(), TruncateSubAuthoritiesError> {
        let new_len = new_len.get();
        if new_len == 0 {
            return Err(TruncateSubAuthoritiesError::EmptySid);
        }
        if new_len < self.sub_authority_count as usize {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "new_len is smaller than an existing valid u8 count"
            )]
            {
                self.sub_authority_count = new_len as u8;
            }
        }
        Ok(())
    }

    /// Owned, stack-allocated Windows **Security Identifier** (SID).
    ///
    /// It can be constructed from raw parts, parsed from text, cloned,
    /// or retrieved from the current user's access token (Windows-only).
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{StackSid, SidIdentifierAuthority};
    /// // Build a SID S-1-5-32-544 (Builtin\Administrators) from parts:
    /// let ia = SidIdentifierAuthority::NT_AUTHORITY; // example ctor
    /// let subs = [32u32, 544u32];
    /// let sid = StackSid::try_new(ia, &subs)
    ///     .expect("valid SID parts");
    /// assert_eq!(sid.revision, 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.sub_authorities(), [32u32, 544u32]);
    /// ```
    /// Creates a new `StackSid` from parts, returning a typed error on invalid input.
    ///
    /// # Errors
    /// Returns [`InvalidSidParts`] if the sub-authority count is outside the valid Windows range.
    #[inline]
    pub const fn try_new(
        identifier_authority: SidIdentifierAuthority,
        sub_authorities: &[u32],
    ) -> Result<Self, InvalidSidParts> {
        if let Err(err) = InvalidSidParts::validate_len(sub_authorities.len()) {
            return Err(err);
        }
        // Safety: We checked the subauthority length to be in 1..=15.
        Ok(unsafe { Self::new_unchecked(identifier_authority, sub_authorities) })
    }

    /// Creates a new `StackSid` from parts **without validation**.
    ///
    /// # Safety
    /// - Caller must ensure `sub_authorities` length is in `1..=15`.
    /// - `identifier_authority` must be a valid Windows authority.
    ///
    /// Violating these preconditions results in undefined behavior or later panics.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{StackSid, SidIdentifierAuthority};
    /// let sid = unsafe{StackSid::new_unchecked(
    ///         SidIdentifierAuthority::NT_AUTHORITY,
    ///         &[32u32, 544u32],
    ///     )};
    /// assert_eq!(sid.revision, 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.sub_authorities(), [32u32, 544u32]);
    /// ```
    #[must_use]
    #[inline]
    pub const unsafe fn new_unchecked(
        identifier_authority: SidIdentifierAuthority,
        sub_authorities: &[u32],
    ) -> Self {
        // initialize array of MaybeUninit
        let mut array = [MaybeUninit::uninit(); MAX_SUBAUTHORITY_COUNT as usize];

        // copy values into the array
        let array_ptr: *mut u32 = array.as_mut_ptr().cast();
        // Safety: We already check the length of sub_authority to be in 1..=15.
        unsafe {
            array_ptr.copy_from_nonoverlapping(sub_authorities.as_ptr(), sub_authorities.len());
        }

        Self {
            revision: Sid::REVISION,
            #[expect(
                clippy::cast_possible_truncation,
                reason = "truncation already checked before"
            )]
            sub_authority_count: sub_authorities.len() as u8,
            identifier_authority,
            sub_authorities: array,
        }
    }

    /// Returns a reference to this `StackSid` as a dynamically-sized [`Sid`].
    ///
    /// This allows a stack allocated `StackSid` to be used as a regular `Sid`
    /// with a trailing slice of sub-authorities.
    #[inline]
    #[must_use]
    pub const fn as_sid(&self) -> &Sid {
        let raw: *const () = ptr::from_ref(self).cast();
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
    pub const fn as_sid_mut(&mut self) -> &mut Sid {
        let raw: *mut () = ptr::from_mut(self).cast();
        // SAFETY: same justification as `as_sid`, but for a mutable reference.
        unsafe { &mut *from_raw_parts_mut(raw, self.sub_authority_count as usize) }
    }

    delegate! {
        to self.as_sid() {
            #[must_use]
            #[inline]
            pub const fn sub_authorities(&self) -> &[u32];
            #[must_use]
            #[inline]
            pub const fn as_bytes(&self) -> &[u8];
            #[must_use]
            #[inline]
            pub const fn last_sub_authority(&self) -> u32;
            #[must_use]
            #[inline]
            pub const fn classification(&self) -> crate::SidClassification;
        }

        to self.as_sid_mut() {
            /// Returns a `&mut [u8]` view over the **currently valid** minimal binary representation.
            ///
            /// This can be used for low-level, in-place updates when you know exactly what you are doing.
            ///
            /// # Safety
            /// - Same preconditions as `as_bytes`.
            /// - Mutating the buffer must preserve SID invariants (e.g., do not desynchronize
            ///   `sub_authority_count` and the tail length).
            #[must_use]
            #[inline]
            pub const unsafe fn as_bytes_mut(&mut self) -> &mut [u8];
        }
    }

    /// Creates a [`StackSid`] from its binary representation.
    ///
    /// `bytes` must contain a serialized Windows SID in the standard layout
    /// (revision, identifier authority, sub-authorities).
    ///
    /// # Errors
    /// Returns `InvalidSidBinaryFormat` if the byte slice is not a valid SID
    /// (e.g., invalid length, revision, or sub-authority count).
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{StackSid, SidIdentifierAuthority};
    /// // Build a SID S-1-5-32-544 (Builtin\Administrators) from parts:
    /// let bytes: [u8; 12] = [
    ///     1, // revision
    ///     1, // sub_authority_count
    ///     0, 0, 0, 0, 0, 5, // identifier_authority (NT AUTHORITY)
    ///     20, 0, 0, 0, // sub_authority[0]
    /// ];
    /// let sid = StackSid::from_bytes(&bytes).expect("valid SID parts");
    /// assert_eq!(sid.revision, 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.sub_authorities(), [20u32]);
    /// ```
    #[inline]
    pub const fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidSidBinaryFormat> {
        if let Err(err) = validate_sid_bytes_unaligned(bytes) {
            return Err(err);
        }
        let mut sid = MaybeUninit::<Self>::uninit();
        // SAFETY: `bytes` was validated immediately above. `StackSid` has the
        // maximum size of a SID.
        unsafe {
            sid.as_mut_ptr()
                .cast::<u8>()
                .copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
        }
        // SAFETY: Initialized by previous copy.
        Ok(unsafe { sid.assume_init() })
    }
}

impl Borrow<Sid> for StackSid {
    #[inline]
    fn borrow(&self) -> &Sid {
        self.as_sid()
    }
}

impl BorrowMut<Sid> for StackSid {
    #[inline]
    fn borrow_mut(&mut self) -> &mut Sid {
        self.as_sid_mut()
    }
}

impl fmt::Debug for StackSid {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        utils::debug_print(stringify!(StackSid), self, f)
    }
}

impl Clone for StackSid {
    #[inline]
    fn clone(&self) -> Self {
        self.as_sid().into()
    }

    #[inline]
    fn clone_from(&mut self, source: &Self) {
        // Safety: Binary copy from another stackSid is safe
        let binary_source = source.as_bytes();
        debug_assert!(
            binary_source.len() <= size_of::<Self>(),
            "StackSid Size should be max size of Sid"
        );
        let len = binary_source.len();
        // SAFETY: Preconditon checked with debug_assert!
        unsafe {
            ptr::from_mut(self)
                .cast::<u8>()
                .copy_from(binary_source.as_ptr(), len);
        }
    }
}

impl AsRef<Sid> for StackSid {
    #[inline]
    fn as_ref(&self) -> &Sid {
        self.as_sid()
    }
}

impl AsRef<[u8]> for StackSid {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> TryFrom<&'a [u8]> for StackSid {
    type Error = InvalidSidBinaryFormat;

    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl From<&Sid> for StackSid {
    #[inline]
    fn from(value: &Sid) -> Self {
        let mut uninit = MaybeUninit::<Self>::uninit();
        let binary_source = value.as_bytes();
        let len = binary_source.len();
        let mem = uninit.as_mut_ptr().cast::<u8>();
        debug_assert!(
            size_of_val(value) <= size_of::<Self>(),
            "StackSid Size should be max size of Sid, it's not true for this value"
        );
        // SAFETY: precondition checked with debug_assert!
        unsafe {
            mem.copy_from_nonoverlapping(binary_source.as_ptr(), len);
        }
        // SAFETY: Initialized by the previous step
        unsafe { uninit.assume_init() }
    }
}

#[cfg(feature = "alloc")]
impl From<SecurityIdentifier> for StackSid {
    #[inline]
    fn from(value: SecurityIdentifier) -> Self {
        value.as_sid().into()
    }
}

#[cfg(feature = "alloc")]
impl From<&SecurityIdentifier> for StackSid {
    #[inline]
    fn from(value: &SecurityIdentifier) -> Self {
        value.as_sid().into()
    }
}

impl<const N: usize> From<ConstSid<N>> for StackSid
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn from(value: ConstSid<N>) -> Self {
        value.as_sid().into()
    }
}

impl FromStr for StackSid {
    type Err = parsing::InvalidSidFormat;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parsing::SidComponents::from_str(s).map(|cmp| {
            debug_assert_eq!(
                MAX_SUBAUTHORITY_COUNT as usize,
                cmp.sub_authorities.capacity(),
                "Verify sub_autority capacity is same as MAX_SUBAUTHORITY_COUNT"
            );
            // SAFETY: All check are done by SidComponents and the debug assertion.
            unsafe {
                Self::new_unchecked(
                    SidIdentifierAuthority::new(cmp.identifier_authority),
                    cmp.sub_authorities.as_slice(),
                )
            }
        })
    }
}

impl Display for StackSid {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_sid())
    }
}

impl PartialEq for StackSid {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_sid().eq(other.as_sid())
    }
}

impl Eq for StackSid {}

impl Hash for StackSid {
    delegate! {
        to self.as_sid() {
            #[inline]
            fn hash<H: core::hash::Hasher>(&self, state: &mut H);
        }
    }
}

impl PartialEq<Sid> for StackSid {
    #[inline]
    fn eq(&self, other: &Sid) -> bool {
        self.as_sid().eq(other)
    }
}

impl<const N: usize> PartialEq<ConstSid<N>> for StackSid
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn eq(&self, other: &ConstSid<N>) -> bool {
        self.as_sid() == other.as_sid()
    }
}

#[cfg(feature = "alloc")]
impl PartialEq<SecurityIdentifier> for StackSid {
    #[inline]
    fn eq(&self, other: &SecurityIdentifier) -> bool {
        self.as_sid() == other.as_sid()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arb_identifier_authority;
    #[cfg(not(has_ptr_metadata))]
    use crate::polyfills_ptr::metadata;
    use crate::well_known;
    use arrayvec::ArrayString;
    use core::fmt::Write;
    #[cfg(has_ptr_metadata)]
    use core::ptr::metadata;
    use proptest::prelude::*;
    pub fn arb_stack_sid() -> impl Strategy<Value = StackSid> {
        (
            arb_identifier_authority(),
            proptest::collection::vec(any::<u32>(), 1..=15),
        )
            .prop_map(|(identifier_authority, sub_authorities)| {
                let subs = &sub_authorities.as_slice();
                StackSid::try_new(identifier_authority, subs).expect("Failed to generate StackSid")
            })
    }

    proptest! {
        #[test]
        fn test_stack_sid_clone(sid in arb_stack_sid()){
            prop_assert_eq!(sid.clone(), sid);

        }

        #[test]
        fn test_stack_sid_clone_from(mut sid in arb_stack_sid(), sid_source in arb_stack_sid()){
            sid.clone_from(&sid_source);
            prop_assert_eq!(sid, sid_source);
        }

        #[test]
        fn test_as_sid_mut(mut sid in arb_stack_sid()){
            let self_addr =ptr::from_mut(&mut sid).addr();
            let sid_ref = sid.as_sid_mut();
            prop_assert_eq!(ptr::from_mut(sid_ref).addr(), self_addr);
            prop_assert_eq!(metadata(sid_ref), sid.sub_authority_count as usize);
        }

        #[test]
        fn test_as_sid(sid in arb_stack_sid()){
            let sid_ref = sid.as_sid();
            prop_assert_eq!(ptr::from_ref(sid_ref).addr(), ptr::from_ref(&sid).addr());
            prop_assert_eq!(metadata(sid_ref), sid.sub_authority_count as usize);
        }
    }
    #[test]
    fn test_from_bytes_copies_unaligned_valid_sid_bytes() {
        let sid = well_known::BUILTIN_ADMINISTRATORS.as_sid();
        let bytes = sid.as_bytes();
        let mut unaligned = [0_u8; 17];
        let unaligned_bytes = {
            let [_, tail @ ..] = &mut unaligned;
            let (sid_bytes, _) = tail.split_at_mut(bytes.len());
            sid_bytes.copy_from_slice(bytes);
            &*sid_bytes
        };

        let stack_sid = StackSid::from_bytes(unaligned_bytes).expect("valid SID bytes");

        assert_eq!(stack_sid.as_sid(), sid);
        assert_eq!(stack_sid.as_bytes(), bytes);
    }

    #[test]
    #[expect(clippy::use_debug, reason = "test verifies Debug output")]
    fn test_debug() {
        let sample_sid = well_known::NULL;
        let stack_sid = StackSid::from(sample_sid.as_sid());
        let mut output = ArrayString::<32>::new();
        assert!(
            write!(&mut output, "{stack_sid:?}").is_ok(),
            "debug output should fit fixed buffer"
        );
        assert_eq!(output.as_str(), "StackSid(S-1-0-0)",);
    }
}
