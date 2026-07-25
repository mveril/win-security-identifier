//! Heap-backed SID storage and mutation.
//!
//! The allocation code below intentionally performs several related pointer
//! operations together: the SID is a dynamically sized type whose metadata is
//! the logical sub-authority count, while the allocation uses a separately
//! tracked capacity bounded by the Windows maximum.
use crate::ConstSid;
use crate::InvalidSidBinaryFormat;
pub use crate::InvalidSidFormat;
use crate::InvalidSidParts;
use crate::Sid;
use crate::SidIdentifierAuthority;
use crate::SidSizeInfo;
use crate::StackSid;
use crate::internal::SidLenValid;
#[cfg(not(has_ptr_metadata))]
use crate::polyfills_ptr::from_raw_parts_mut;
use crate::sid::SidHead;
use crate::utils;
use crate::utils::validate_sid_bytes_unaligned;
use crate::{
    ExtendSubAuthoritiesError, PopSubAuthoritiesError, PopSubAuthorityError, PoppedSubAuthorities,
    PushSubAuthorityError, TruncateSubAuthoritiesError,
};
#[cfg(all(feature = "alloc", not(feature = "std")))]
use ::alloc::{alloc, borrow::ToOwned, boxed::Box};
use core::fmt::{self, Debug, Display};
use core::mem::{ManuallyDrop, offset_of};
use core::ops::Deref;
#[cfg(has_ptr_metadata)]
use core::ptr::from_raw_parts_mut;
use core::ptr::{NonNull, addr_of, addr_of_mut};
mod maybe_uninit;
use core::borrow::{Borrow, BorrowMut};
use core::num::NonZeroUsize;
use core::ops::DerefMut;
use core::str::FromStr;
use maybe_uninit::MaybeUninitSecurityIdentifier;
use parsing::SidComponents;
#[cfg(feature = "std")]
use std::{alloc, borrow::ToOwned};

/// Owned, heap-allocated Windows **Security Identifier** (SID).
///
/// This type owns the underlying SID memory and guarantees:
/// - Proper allocation according to the number of sub-authorities.
/// - Proper deallocation via `Drop`.
/// - Safe read/write access through `Deref`/`DerefMut` to the inner [Sid].
///
/// It can be constructed from raw parts, parsed from text, cloned,
/// or retrieved from the current user's access token (Windows-only).
///
///
/// # Examples
/// ```rust
/// # use win_security_identifier::{SecurityIdentifier, SidIdentifierAuthority};
/// // Build a SID S-1-5-32-544 (Builtin\Administrators) from parts:
/// let ia = SidIdentifierAuthority::NT_AUTHORITY; // example ctor
/// let subs = [32u32, 544u32];
/// let sid = SecurityIdentifier::try_new(ia, &subs)
///     .expect("valid SID parts");
/// println!("{}", sid); // e.g., "S-1-5-32-544"
/// ```
pub struct SecurityIdentifier {
    // Points to a global-allocator allocation aligned for `SidHead`. Its layout
    // corresponds to `capacity`; the initialized SID length is stored in
    // `SidHead::sub_authority_count` and never exceeds that capacity.
    inner: NonNull<u8>,
    capacity: u8,
}

// SAFETY: `SecurityIdentifier` exclusively owns its global-allocator allocation.
// Moving it transfers that ownership without changing the allocation, and all
// access to the SID contents still requires Rust's shared or exclusive borrow
// rules.
unsafe impl Send for SecurityIdentifier {}

// SAFETY: shared access only exposes `&Sid`; mutations require `&mut self`.
// The allocation remains valid until `Drop`, which requires exclusive access to
// the owning value.
unsafe impl Sync for SecurityIdentifier {}

impl Debug for SecurityIdentifier {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        utils::debug_print::<Self>(stringify!(SecurityIdentifier), self, f)
    }
}

impl SecurityIdentifier {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::multiple_unsafe_ops_per_block,
        reason = "the SID limit guarantees the new count fits in u8; the pointer operations initialize one DST tail"
    )]
    fn grow_by(&mut self, appended: &[u32]) {
        let new_count = self.sub_authorities().len() + appended.len();
        debug_assert!(
            new_count <= crate::sid_mutation::max_sub_authorities(),
            "the new SID length must remain within the Windows limit"
        );
        self.reserve_for(appended.len());
        let old_count = self.sub_authorities().len();
        // SAFETY: reserve guarantees enough storage, and the destination is the
        // uninitialized tail immediately following the logical SID.
        unsafe {
            let sid_ptr: *mut Sid = from_raw_parts_mut(self.inner.as_ptr().cast::<()>(), new_count);
            addr_of_mut!((*sid_ptr).sub_authorities)
                .cast::<u32>()
                .add(old_count)
                .copy_from_nonoverlapping(appended.as_ptr(), appended.len());
            addr_of_mut!((*self.inner.as_ptr().cast::<SidHead>()).sub_authority_count)
                .write(new_count as u8);
        }
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::multiple_unsafe_ops_per_block,
        reason = "the capacity invariant guarantees the new count fits in u8; the pointer operations update one SID header"
    )]
    fn shrink_to(&mut self, new_count: usize) {
        debug_assert!(
            (1..=self.capacity()).contains(&new_count),
            "the new SID length must fit the allocation"
        );
        // SAFETY: the header is initialized and `new_count` fits the allocation.
        unsafe {
            addr_of_mut!((*self.inner.as_ptr().cast::<SidHead>()).sub_authority_count)
                .write(new_count as u8);
        }
    }

    /// Returns the number of sub-authorities that fit without reallocating.
    #[must_use]
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.capacity as usize
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::multiple_unsafe_ops_per_block,
        reason = "the Windows SID limit guarantees the capacity fits in u8; the allocator operations form one reallocation"
    )]
    fn reserve_for(&mut self, additional: usize) {
        let required = self.sub_authorities().len().saturating_add(additional);
        debug_assert!(
            required <= crate::sid_mutation::max_sub_authorities(),
            "the required SID capacity must remain within the Windows limit"
        );
        if required <= self.capacity() {
            return;
        }
        let max = crate::sid_mutation::max_sub_authorities();
        let new_capacity = self.capacity().saturating_mul(2).max(required).min(max);
        // SAFETY: both layouts have the same alignment and `inner` was allocated
        // by the global allocator with `old_layout`.
        unsafe {
            let old_layout = SidSizeInfo::from_count(self.capacity)
                .unwrap_unchecked()
                .layout();
            let new_layout = SidSizeInfo::from_count(new_capacity as u8)
                .unwrap_unchecked()
                .layout();
            let resized = alloc::realloc(self.inner.as_ptr(), old_layout, new_layout.size());
            self.inner =
                NonNull::new(resized).unwrap_or_else(|| alloc::handle_alloc_error(new_layout));
        }
        self.capacity = new_capacity as u8;
    }

    /// Reserves capacity for at least `additional` more sub-authorities.
    ///
    /// # Errors
    /// Returns [`ExtendSubAuthoritiesError`] when the requested capacity exceeds
    /// the Windows limit of 15 sub-authorities.
    #[inline]
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), ExtendSubAuthoritiesError> {
        let current = self.sub_authorities().len();
        let max = crate::sid_mutation::max_sub_authorities();
        if additional > max.saturating_sub(current) {
            return Err(ExtendSubAuthoritiesError::TooManySubAuthorities { current, max });
        }
        self.reserve_for(additional);
        Ok(())
    }

    /// Shrinks the allocation to the current logical SID length.
    #[inline]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::multiple_unsafe_ops_per_block,
        reason = "a valid SID length fits in u8; the allocator operations form one reallocation"
    )]
    pub fn shrink_to_fit(&mut self) {
        let len = self.sub_authorities().len();
        if len == self.capacity() {
            return;
        }
        // SAFETY: `len` is a valid SID count no larger than the current capacity.
        unsafe {
            let old_layout = SidSizeInfo::from_count(self.capacity)
                .unwrap_unchecked()
                .layout();
            let new_layout = SidSizeInfo::from_count(len as u8)
                .unwrap_unchecked()
                .layout();
            let resized = alloc::realloc(self.inner.as_ptr(), old_layout, new_layout.size());
            self.inner =
                NonNull::new(resized).unwrap_or_else(|| alloc::handle_alloc_error(new_layout));
        }
        self.capacity = len as u8;
    }

    /// Appends one sub-authority, growing the allocation when capacity is exhausted.
    ///
    /// # Errors
    /// Returns [`PushSubAuthorityError`] if the SID already has 15 sub-authorities.
    #[inline]
    pub fn try_push_sub_authority(&mut self, value: u32) -> Result<(), PushSubAuthorityError> {
        if self.sub_authorities().len() == crate::sid_mutation::max_sub_authorities() {
            return Err(PushSubAuthorityError::MaximumSubAuthoritiesReached {
                max: crate::sid_mutation::max_sub_authorities(),
            });
        }
        self.grow_by(core::slice::from_ref(&value));
        Ok(())
    }

    /// Collects and appends an iterator, growing the allocation at most once.
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
        let current = self.sub_authorities().len();
        let max = crate::sid_mutation::max_sub_authorities();
        let mut pending = arrayvec::ArrayVec::<u32, 15>::new();
        for value in values {
            if current + pending.len() == max || pending.try_push(value).is_err() {
                return Err(ExtendSubAuthoritiesError::TooManySubAuthorities { current, max });
            }
        }
        if !pending.is_empty() {
            self.grow_by(pending.as_slice());
        }
        Ok(())
    }

    /// Removes and returns the final sub-authority without reducing capacity.
    ///
    /// # Errors
    /// Returns [`PopSubAuthorityError`] if removing the value would empty the SID.
    #[inline]
    pub fn try_pop_sub_authority(&mut self) -> Result<u32, PopSubAuthorityError> {
        let current = self.sub_authorities().len();
        if current == 1 {
            return Err(PopSubAuthorityError::CannotRemoveLastSubAuthority);
        }
        let value = self.last_sub_authority();
        self.shrink_to(current - 1);
        Ok(value)
    }

    /// Removes several trailing sub-authorities without reducing capacity.
    ///
    /// Removed values are returned in their original order.
    ///
    /// # Errors
    /// Returns [`PopSubAuthoritiesError`] if `count` would empty the SID.
    #[inline]
    pub fn try_pop_sub_authorities(
        &mut self,
        count: usize,
    ) -> Result<PoppedSubAuthorities, PopSubAuthoritiesError> {
        let current = self.sub_authorities().len();
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
        if count != 0 {
            self.shrink_to(new_count);
        }
        Ok(removed)
    }

    /// Truncates trailing sub-authorities without reducing capacity.
    ///
    /// # Errors
    /// Returns [`TruncateSubAuthoritiesError`] when `new_len` is zero.
    #[inline]
    pub fn try_truncate_sub_authorities(
        &mut self,
        new_len: NonZeroUsize,
    ) -> Result<(), TruncateSubAuthoritiesError> {
        let new_len = new_len.get();
        if new_len == 0 {
            return Err(TruncateSubAuthoritiesError::EmptySid);
        }
        if new_len < self.sub_authorities().len() {
            self.shrink_to(new_len);
        }
        Ok(())
    }

    /// Creates a new `SecurityIdentifier` from parts, returning a typed error on invalid input.
    ///
    /// # Parameters
    /// - `identifier_authority`: High-level authority (e.g. `NT_AUTHORITY`).
    /// - `sub_authorities`: Slice of sub-authorities (1..=15 elements).
    ///
    /// # Errors
    /// Returns [`InvalidSidParts`] if the sub-authority count is outside the valid Windows range.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, SidIdentifierAuthority};
    /// let sid = SecurityIdentifier::try_new(
    ///     SidIdentifierAuthority::NT_AUTHORITY,
    ///     [32u32, 544u32]
    /// ).unwrap();
    /// assert_eq!(sid.revision(), 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.sub_authorities(), [32u32, 544u32]);
    /// ```
    #[inline]
    pub fn try_new<I: Into<SidIdentifierAuthority>, S: AsRef<[u32]>>(
        identifier_authority: I,
        sub_authorities: S,
    ) -> Result<Self, InvalidSidParts> {
        let sub_authorities = sub_authorities.as_ref();
        // SAFETY: sub_authority_count is correctly validated by guard.
        InvalidSidParts::validate_len(sub_authorities.len())?;
        // SAFETY: The length has just been validated, so the unchecked constructor
        // receives a sub-authority slice within the supported Windows range.
        Ok(unsafe { Self::new_unchecked(identifier_authority, sub_authorities) })
    }

    /// Creates a new `SecurityIdentifier` from parts **without validation**.
    ///
    /// # Safety
    /// - Caller must ensure `sub_authorities` length is in `1..=15`.
    /// - `identifier_authority` must be a valid Windows authority.
    ///
    /// Violating these preconditions results in undefined behavior or later panics.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, SidIdentifierAuthority};
    /// let sid = unsafe {
    ///     SecurityIdentifier::new_unchecked(
    ///         SidIdentifierAuthority::NT_AUTHORITY,
    ///         [32u32, 544u32],
    ///     )
    /// };
    /// assert_eq!(sid.revision(), 1);
    /// assert_eq!(sid.identifier_authority, SidIdentifierAuthority::NT_AUTHORITY);
    /// assert_eq!(sid.sub_authorities(), [32u32, 544u32]);
    /// ```
    #[must_use]
    #[inline]
    pub unsafe fn new_unchecked<I: Into<SidIdentifierAuthority>, S: AsRef<[u32]>>(
        identifier_authority: I,
        sub_authorities: S,
    ) -> Self {
        let sub_authorities = sub_authorities.as_ref();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Precondition of sub_authority_is_checked in the doc."
        )]
        let sub_authority_count = sub_authorities.len() as u8;
        let identifier_authority = identifier_authority.into();
        // SAFETY: sub_authority_count is validated by guard.
        let size_info = unsafe { SidSizeInfo::from_count(sub_authority_count).unwrap_unchecked() };
        // Safety: The uninit SID will be correctly filled after.
        let mut uninit = MaybeUninitSecurityIdentifier::alloc(&size_info);
        let sid_ptr = uninit.as_mut_ptr();
        // SAFETY: The allocation was sized for the validated sub-authority
        // count, and `sid_ptr` points to its writable SID storage.
        unsafe {
            Sid::initialize(
                sid_ptr,
                sub_authority_count,
                identifier_authority,
                sub_authorities,
            );
        }
        // Safety: all is written so we can assume init
        unsafe { uninit.assume_init() }
    }

    /// Creates a `SecurityIdentifier` from a byte slice.
    ///
    /// This function attempts to parse a byte slice into a valid `SecurityIdentifier`.
    ///
    /// # Parameters
    /// - `bytes`: A type that can be referenced as a byte slice (`AsRef<[u8]>`).
    ///
    /// # Errors
    /// - [`InvalidSidBinaryFormat`] If the byte slice is not a valid SID binary format.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, InvalidSidBinaryFormat};
    /// // SID: S-1-5-32-544 (Administrators)
    /// let bytes: [u8; 16] = [
    ///     1,    // Revision
    ///     2,    // SubAuthorityCount
    ///     0, 0, 0, 0, 0, 5, // IdentifierAuthority = NT AUTHORITY
    ///     32, 0, 0, 0,      // SubAuthority[0] = 32
    ///     32, 2, 0, 0       // SubAuthority[1] = 544 (0x220 little endian)
    /// ];
    /// let sid = SecurityIdentifier::from_bytes(&bytes);
    /// assert!(sid.is_ok());
    /// assert!(sid.unwrap().to_string() == "S-1-5-32-544")
    /// ```
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidSidBinaryFormat> {
        validate_sid_bytes_unaligned(bytes)?;
        // SAFETY: All check was done before
        Ok(unsafe { Self::from_bytes_unchecked(bytes) })
    }

    /// Builds a `SecurityIdentifier` from raw bytes without validation.
    ///
    /// # Safety
    /// The caller must ensure `bytes` encodes a valid SID, with a length that
    /// matches the embedded `sub_authority_count` and the expected binary
    /// layout. Passing invalid bytes results in undefined behavior.
    #[inline]
    unsafe fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        #[expect(
            clippy::indexing_slicing,
            reason = "The unchecked constructor requires a valid SID byte layout"
        )]
        let sub_authority_count = bytes[offset_of!(Sid, sub_authority_count)];
        // SAFETY: All safety criteria are described in the doc.
        let size_info = unsafe { SidSizeInfo::from_count(sub_authority_count).unwrap_unchecked() };
        // Safety: The uninit SID is properly initialized by copying from `self` after.
        let mut uninit = MaybeUninitSecurityIdentifier::alloc(&size_info);
        // Safety: We copy all the bytes from a valid SID of the same size.
        unsafe {
            uninit
                .as_mut_ptr()
                .cast::<u8>()
                .copy_from_nonoverlapping(bytes.as_ptr(), size_info.layout().size());
        }
        // Safety: all is written so we can init.
        unsafe { uninit.assume_init() }
    }

    /// Returns a reference to this `SecurityIdentifier` as a dynamically-sized [`Sid`].
    ///
    /// This allows treating owned `SecurityIdentifier` as a regular `Sid`
    /// with a trailing slice of sub-authorities.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, SidIdentifierAuthority, Sid};
    /// let admin = SecurityIdentifier::try_new(
    ///     SidIdentifierAuthority::NT_AUTHORITY,
    ///     [32, 544],
    /// ).unwrap();
    /// let sid: &Sid = admin.as_sid();
    /// assert_eq!(sid.to_string(), "S-1-5-32-544");
    /// ```
    #[inline]
    #[must_use]
    #[allow(
        clippy::multiple_unsafe_ops_per_block,
        reason = "reading the SID header and constructing its DST reference are one validated operation"
    )]
    pub fn as_sid(&self) -> &Sid {
        // SAFETY: `inner` points to an initialized SID header for the lifetime
        // of self. The logical count is maintained in 1..=capacity.
        unsafe {
            let count = addr_of!((*self.inner.as_ptr().cast::<SidHead>()).sub_authority_count)
                .read() as usize;
            debug_assert!(
                (1..=self.capacity()).contains(&count),
                "the logical SID length must fit the allocation"
            );
            &*from_raw_parts_mut(self.inner.as_ptr().cast::<()>(), count)
        }
    }

    /// Returns a mut reference to this `SecurityIdentifier` as a dynamically-sized [`Sid`].
    ///
    /// This allows treating owned `SecurityIdentifier` as a regular `Sid`
    /// with a trailing slice of sub-authorities.
    ///
    /// # Examples
    /// ```rust
    /// # use win_security_identifier::{SecurityIdentifier, Sid, SidIdentifierAuthority};
    /// #
    /// // Create a mutable ConstSid with three sub-authorities:
    /// // S-1-5-21-1000 (revision 1, authority 5, sub-authorities [21, 1000])
    /// let mut owned = SecurityIdentifier::try_new(
    ///     SidIdentifierAuthority::NT_AUTHORITY,
    ///     &[21u32, 100u32, 0u32],
    /// ).unwrap();
    ///
    /// // Get a mutable `&mut Sid` referencing the same memory.
    /// // From here we can mutate sub-authorities in-place without re-allocating.
    /// let sid_mut: &mut Sid = owned.as_sid_mut();
    ///
    /// // Modify the last sub-authority in-place.
    /// // (Assumes the `Sid` type exposes a mutable slice accessor.)
    /// sid_mut.identifier_authority = SidIdentifierAuthority::NULL_AUTHORITY;
    ///
    /// // The string representation reflects the in-place change.
    /// assert_eq!(sid_mut.to_string(), "S-1-0-21-100-0");
    /// ```
    #[inline]
    #[allow(
        clippy::multiple_unsafe_ops_per_block,
        reason = "reading the SID header and constructing its mutable DST reference are one validated operation"
    )]
    pub fn as_sid_mut(&mut self) -> &mut Sid {
        // SAFETY: exclusive access to self guarantees exclusive access to the
        // initialized logical SID prefix.
        unsafe {
            let count = addr_of!((*self.inner.as_ptr().cast::<SidHead>()).sub_authority_count)
                .read() as usize;
            debug_assert!(
                (1..=self.capacity()).contains(&count),
                "the logical SID length must fit the allocation"
            );
            &mut *from_raw_parts_mut(self.inner.as_ptr().cast::<()>(), count)
        }
    }
}

impl TryFrom<&[u8]> for SecurityIdentifier {
    type Error = InvalidSidBinaryFormat;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl<'a> From<&'a Sid> for SecurityIdentifier {
    #[inline]
    fn from(value: &'a Sid) -> Self {
        let binary = value.as_bytes();
        // Safety: sub_authority_count is known to be valid because `self` is valid.
        unsafe { Self::from_bytes_unchecked(binary) }
    }
}

impl FromStr for SecurityIdentifier {
    type Err = InvalidSidFormat;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let components = SidComponents::from_str(s)?;
        Ok(
            // SAFETY: sub_authority_count is known to be valid because `SidComponents::from_str` validated it.
            unsafe {
                Self::new_unchecked(
                    components.identifier_authority,
                    components.sub_authorities.as_slice(),
                )
            },
        )
    }
}

impl ToOwned for Sid {
    type Owned = super::SecurityIdentifier;
    #[inline]
    fn to_owned(&self) -> Self::Owned {
        self.into()
    }
}

impl Borrow<Sid> for SecurityIdentifier {
    #[inline]
    fn borrow(&self) -> &Sid {
        self.as_sid()
    }
}

impl BorrowMut<Sid> for SecurityIdentifier {
    #[inline]
    fn borrow_mut(&mut self) -> &mut Sid {
        self.as_sid_mut()
    }
}

impl Deref for SecurityIdentifier {
    type Target = Sid;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_sid()
    }
}

impl DerefMut for SecurityIdentifier {
    #[inline]
    fn deref_mut(&mut self) -> &mut Sid {
        self.as_sid_mut()
    }
}

impl SecurityIdentifier {
    #[must_use]
    #[inline]
    pub fn classification(&self) -> crate::SidClassification {
        self.as_sid().classification()
    }
}

impl AsRef<Sid> for SecurityIdentifier {
    #[inline]
    fn as_ref(&self) -> &Sid {
        self.as_sid()
    }
}

impl AsRef<[u8]> for SecurityIdentifier {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<Sid> for SecurityIdentifier {
    #[inline]
    fn as_mut(&mut self) -> &mut Sid {
        self.as_sid_mut()
    }
}

impl Clone for SecurityIdentifier {
    #[inline]
    fn clone(&self) -> Self {
        self.as_sid().into()
    }
    #[inline]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "a valid SID contains at most 15 sub-authorities and therefore fits in u8"
    )]
    fn clone_from(&mut self, source: &Self) {
        let source_len = source.sub_authorities().len();
        let additional = source_len.saturating_sub(self.sub_authorities().len());
        self.reserve_for(additional);
        let source_size = SidSizeInfo::from_count(source_len as u8)
            .map(|info| info.layout().size())
            .unwrap_or_default();
        debug_assert_ne!(source_size, 0, "a valid SID allocation is never empty");
        // SAFETY: reserve_for guarantees sufficient capacity for the complete
        // logical source SID, and mutable and shared references cannot alias.
        unsafe {
            self.inner
                .as_ptr()
                .copy_from_nonoverlapping(source.inner.as_ptr(), source_size);
        }
    }
}

impl Display for SecurityIdentifier {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self.as_sid(), f)
    }
}

impl Eq for SecurityIdentifier {}

impl PartialEq<Sid> for SecurityIdentifier {
    #[inline]
    fn eq(&self, other: &Sid) -> bool {
        AsRef::<Sid>::as_ref(self) == other
    }
}

impl<const N: usize> PartialEq<ConstSid<N>> for SecurityIdentifier
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn eq(&self, other: &ConstSid<N>) -> bool {
        self.eq(other.as_sid())
    }
}

impl PartialEq<StackSid> for SecurityIdentifier {
    #[inline]
    fn eq(&self, other: &StackSid) -> bool {
        self == other.as_sid()
    }
}

impl PartialEq for SecurityIdentifier {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_sid() == other.as_sid()
    }
}

impl From<Box<Sid>> for SecurityIdentifier {
    #[inline]
    fn from(value: Box<Sid>) -> Self {
        let capacity = value.sub_authority_count;
        let raw = Box::into_raw(value).cast::<u8>();
        // SAFETY: Box pointers are always non-null.
        let inner = unsafe { NonNull::new_unchecked(raw) };
        Self { inner, capacity }
    }
}

impl From<StackSid> for SecurityIdentifier {
    #[inline]
    fn from(value: StackSid) -> Self {
        value.as_sid().into()
    }
}

impl From<&StackSid> for SecurityIdentifier {
    #[inline]
    fn from(value: &StackSid) -> Self {
        value.as_sid().into()
    }
}

impl<const N: usize> From<ConstSid<N>> for SecurityIdentifier
where
    [u32; N]: SidLenValid,
{
    #[inline]
    fn from(value: ConstSid<N>) -> Self {
        value.as_sid().to_owned()
    }
}

impl From<SecurityIdentifier> for Box<Sid> {
    #[inline]
    fn from(mut value: SecurityIdentifier) -> Self {
        value.shrink_to_fit();
        let value = ManuallyDrop::new(value);
        let count = value.capacity as usize;
        let raw = from_raw_parts_mut(value.inner.as_ptr().cast::<()>(), count);
        // SAFETY: shrink_to_fit made the allocation layout exactly match this DST.
        unsafe { Self::from_raw(raw) }
    }
}

impl Drop for SecurityIdentifier {
    #[inline]
    #[allow(
        clippy::multiple_unsafe_ops_per_block,
        reason = "recovering the allocation layout and deallocating it form one drop operation"
    )]
    fn drop(&mut self) {
        // SAFETY: the allocation was created by the global allocator with the
        // layout corresponding to capacity and remains owned by self.
        unsafe {
            let layout = SidSizeInfo::from_count(self.capacity)
                .unwrap_unchecked()
                .layout();
            alloc::dealloc(self.inner.as_ptr(), layout);
        }
    }
}

impl From<&Sid> for Box<Sid> {
    #[inline]
    fn from(value: &Sid) -> Self {
        SecurityIdentifier::from(value).into()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Unwrap is not an issue in test")]
#[allow(clippy::expect_used, reason = "Expect is not an issue in test")]
pub mod test {
    use super::super::SecurityIdentifier;
    use super::super::Sid;
    use super::super::sid_identifier_authority::test::arb_identifier_authority;
    #[cfg(not(has_ptr_metadata))]
    use crate::polyfills_ptr::metadata;
    use crate::well_known;
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    use alloc::format;
    #[cfg(feature = "std")]
    use core::hash::{Hash, Hasher};
    #[cfg(has_ptr_metadata)]
    use core::ptr::metadata;
    use proptest::prelude::*;
    pub fn arb_security_identifier() -> impl Strategy<Value = SecurityIdentifier> {
        (
            arb_identifier_authority(),
            proptest::collection::vec(any::<u32>(), 1..=15),
        )
            .prop_map(|(identifier_authority, sub_authorities)| {
                let subs = &sub_authorities.as_slice();
                SecurityIdentifier::try_new(identifier_authority, subs)
                    .expect("Failed to generate SecurityIdentifier")
            })
    }

    proptest! {
        #[test]
        #[cfg(feature = "std")]
        fn test_sid_properties(security_identifier in arb_security_identifier()) {
            // Hash
            use std::collections::hash_map::DefaultHasher;
            // Test access to inner Sid
            let sid: &Sid = security_identifier.as_ref();

            // Check length of sub_authorities
            assert_eq!(sid.sub_authorities().len(), sid.sub_authority_count as usize);

            // Display format: commence par S-1-
            let disp = format!("{sid}");
            prop_assert!(disp.starts_with("S-1-"), "Display doesn't start with S-1- : {}", disp);

            // ToOwned et Eq
            let owned_sid = sid.to_owned();
            let sid2 = &*owned_sid;
            prop_assert_eq!(sid, sid2, "to_owned then deref should yield eq sids");

            let mut h1 = DefaultHasher::new();
            sid.hash(&mut h1);
            let mut h2 = DefaultHasher::new();
            sid2.hash(&mut h2);
            prop_assert_eq!(h1.finish(), h2.finish(), "Hashes should match for equal SIDs");
        }

        #[test]
        #[cfg(feature="std")]
        fn test_securityidentifier_eq_and_hash(a in arb_security_identifier(), b in arb_security_identifier()) {
            // Reflexivity
            prop_assert_eq!(&*a, &*a);

            // Hash: equal => hash equal
            if *a == *b {
                let mut ha = std::collections::hash_map::DefaultHasher::new();
                let mut hb = std::collections::hash_map::DefaultHasher::new();
                a.hash(&mut ha);
                b.hash(&mut hb);
                prop_assert_eq!(ha.finish(), hb.finish(), "Hashes must be equal for identical SIDs");
            }
        }

        #[test]
        fn test_sub_authority_slice_bounds(security_identifier in arb_security_identifier()) {
            let sid: &Sid = &security_identifier;
            let subs = sid.sub_authorities();
            assert!(!subs.is_empty() && subs.len() <= 15, "sub_authorities length must be in 1..=15");
        }

         #[test]
        fn test_ptr_metadata(security_identifier in arb_security_identifier()) {
            let sid: &Sid = &security_identifier;
            prop_assert_eq!(sid.sub_authority_count as usize, sid.sub_authorities().len());
            prop_assert_eq!(sid.sub_authority_count as usize, metadata(sid));
        }

        #[test]
        #[cfg(feature="std")]
        fn test_sid_to_string_from_string(sid1 in arb_security_identifier()){
            let sid2: SecurityIdentifier = sid1.to_string().parse().unwrap();
            prop_assert_eq!(sid1, sid2);
        }

        fn test_security_identifier_clone(sid in arb_security_identifier()){
            prop_assert_eq!(sid.clone(), sid);

        }

        #[test]
        fn test_security_identifier_clone_from(mut sid in arb_security_identifier(), sid_source in arb_security_identifier()){
            sid.clone_from(&sid_source);
            prop_assert_eq!(sid, sid_source);
        }
    }

    #[cfg(all(feature = "std", windows, not(miri)))]
    mod windows {
        use core::ptr;
        use core::slice;

        use super::arb_security_identifier;
        use proptest::prelude::*;
        use windows_sys::Win32::Security::*;

        proptest! {
            #[test]
            fn test_init_sid_matches_rust_bytes(sid in arb_security_identifier()) {
                let subauth = sid.sub_authorities();
                #[expect(clippy::cast_possible_truncation, reason="No truncation here because of range of subathority is between 1-15")]
                let n = subauth.len() as u8;
                // SAFETY: GetSidLengthRequired is safe for sid Length
                let required_size = unsafe { GetSidLengthRequired(n) } as usize;
                let mut buffer = Vec::<u8>::with_capacity(required_size);
                #[expect(clippy::cast_ptr_alignment, reason = "Unaligned pointer is not an issue for windows API")]
                let sid_ptr = buffer.as_mut_ptr().cast::<SID>();
                // SAFETY: InitializeSid is ok with the good buffer.
                #[expect(clippy::multiple_unsafe_ops_per_block, reason="Not realy an issue in tests")]
                unsafe {
                    let ok = InitializeSid(
                        sid_ptr.cast(),
                        ptr::from_ref(&sid.identifier_authority).cast::<SID_IDENTIFIER_AUTHORITY>(),
                        n,
                    );
                    prop_assert!(ok != 0, "InitializeSid failed");
                    buffer.set_len(required_size);
                    for (i, &sa) in subauth.iter().enumerate() {
                        let ptr = GetSidSubAuthority(sid_ptr.cast(), u32::try_from(i).unwrap());
                        prop_assert!(!ptr.is_null(), "GetSidSubAuthority null at index {}", i);
                        *ptr = sa;
                    }

                    let win_len = GetLengthSid(sid_ptr.cast());
                    let win_bytes = slice::from_raw_parts(sid_ptr as *const u8, win_len as usize);

                    let rust_bytes = sid.as_bytes();
                    prop_assert_eq!(
                        win_bytes,
                        rust_bytes,
                        "The Windows SID must match the binary Rust SID."
                    );
                }
            }
        }
    }
    #[test]
    fn test_from_bytes_unchecked_copies_valid_sid_bytes() {
        let sid = well_known::BUILTIN_ADMINISTRATORS.as_sid();
        let bytes = sid.as_bytes();
        // SAFETY: `bytes` comes from a valid SID.
        let owned_sid = unsafe { SecurityIdentifier::from_bytes_unchecked(bytes) };

        assert_eq!(owned_sid.as_sid(), sid);
        assert_eq!(owned_sid.as_bytes(), bytes);
    }

    #[test]
    fn test_from_bytes_unchecked_copies_unaligned_valid_sid_bytes() {
        let sid = well_known::BUILTIN_ADMINISTRATORS.as_sid();
        let bytes = sid.as_bytes();
        let mut unaligned = [0_u8; 17];
        let unaligned_bytes = {
            let [_, tail @ ..] = &mut unaligned;
            let (sid_bytes, _) = tail.split_at_mut(bytes.len());
            sid_bytes.copy_from_slice(bytes);
            &*sid_bytes
        };

        // SAFETY: `unaligned_bytes` contains a valid SID binary layout. This
        // constructor copies bytes and does not create a `&Sid` from the source.
        let owned_sid = unsafe { SecurityIdentifier::from_bytes_unchecked(unaligned_bytes) };

        assert_eq!(owned_sid.as_sid(), sid);
        assert_eq!(owned_sid.as_bytes(), bytes);
    }

    #[test]
    fn test_debug() {
        let sample_sid = well_known::NULL;
        assert_eq!(
            format!("{:?}", SecurityIdentifier::from(sample_sid.as_sid())),
            format!("{:}(S-1-0-0)", stringify!(SecurityIdentifier)),
        );
    }

    #[test]
    fn security_identifier_is_send_and_sync() {
        fn assert_send_and_sync<T: Send + Sync>() {}

        assert_send_and_sync::<SecurityIdentifier>();
    }
}
