use arrayvec::ArrayVec;
use core::{fmt, slice};
use thiserror::Error;

pub const MAX_SUB_AUTHORITIES: usize = parsing::MAX_SUBAUTHORITY_COUNT as usize;

/// Error returned when a sub-authority cannot be appended to a SID.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PushSubAuthorityError {
    /// The SID already contains the maximum number of sub-authorities.
    #[error("cannot push a sub-authority: the SID already contains the maximum of {max}")]
    MaximumSubAuthoritiesReached { max: usize },
}

/// Error returned when an iterator cannot be appended to a SID.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExtendSubAuthoritiesError {
    /// Consuming the iterator would exceed the Windows SID limit.
    #[error("cannot extend a SID containing {current} sub-authorities beyond the maximum of {max}")]
    TooManySubAuthorities { current: usize, max: usize },
}

/// Error returned when one sub-authority cannot be removed from a SID.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PopSubAuthorityError {
    /// Removing the value would leave an invalid empty SID.
    #[error("cannot remove the SID's last sub-authority")]
    CannotRemoveLastSubAuthority,
}

/// Error returned when several sub-authorities cannot be removed from a SID.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PopSubAuthoritiesError {
    /// The request would remove more values than the SID can safely lose.
    #[error("cannot remove {requested} sub-authorities; at most {available} can be removed")]
    InsufficientSubAuthorities { requested: usize, available: usize },
}

/// Error returned when a SID cannot be truncated to the requested length.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TruncateSubAuthoritiesError {
    /// A valid SID must retain at least one sub-authority.
    #[error("cannot truncate a SID to zero sub-authorities")]
    EmptySid,
}

/// Owned sub-authorities removed from the end of a SID.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct PoppedSubAuthorities {
    values: ArrayVec<u32, MAX_SUB_AUTHORITIES>,
}

impl PoppedSubAuthorities {
    pub(crate) fn try_from_slice(values: &[u32]) -> Option<Self> {
        if values.len() > MAX_SUB_AUTHORITIES {
            return None;
        }
        let mut result = Self::default();
        for &value in values {
            if result.values.try_push(value).is_err() {
                return None;
            }
        }
        Some(result)
    }

    /// Returns the removed values in their original order.
    #[must_use]
    #[inline]
    pub fn as_slice(&self) -> &[u32] {
        self.values.as_slice()
    }

    /// Returns an iterator over the removed values in their original order.
    #[inline]
    pub fn iter(&self) -> slice::Iter<'_, u32> {
        self.values.iter()
    }

    /// Returns the number of removed sub-authorities.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns whether no sub-authorities were removed.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl AsRef<[u32]> for PoppedSubAuthorities {
    #[inline]
    fn as_ref(&self) -> &[u32] {
        self.as_slice()
    }
}

impl<'a> IntoIterator for &'a PoppedSubAuthorities {
    type Item = &'a u32;
    type IntoIter = slice::Iter<'a, u32>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for PoppedSubAuthorities {
    type Item = u32;
    type IntoIter = arrayvec::IntoIter<u32, MAX_SUB_AUTHORITIES>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

impl fmt::Debug for PoppedSubAuthorities {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

pub const fn max_sub_authorities() -> usize {
    MAX_SUB_AUTHORITIES
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use crate::SidSizeInfo;
    use crate::{SidIdentifierAuthority, StackSid};
    #[cfg(feature = "alloc")]
    use core::alloc::Layout;
    #[cfg(feature = "alloc")]
    use core::num::NonZeroUsize;
    use proptest::prelude::*;

    #[cfg(feature = "alloc")]
    use crate::SecurityIdentifier;

    fn stack(values: &[u32]) -> StackSid {
        StackSid::try_new(SidIdentifierAuthority::NT_AUTHORITY, values)
            .expect("generated sub-authority count is valid")
    }

    #[cfg(feature = "alloc")]
    fn heap(values: &[u32]) -> SecurityIdentifier {
        SecurityIdentifier::try_new(SidIdentifierAuthority::NT_AUTHORITY, values)
            .expect("generated sub-authority count is valid")
    }

    #[cfg(feature = "alloc")]
    fn assert_logical_heap_layout(sid: &SecurityIdentifier) {
        let count =
            u8::try_from(sid.sub_authorities().len()).expect("a valid SID count always fits in u8");
        let expected = SidSizeInfo::from_count(count).expect("count belongs to a valid SID");
        assert_eq!(Layout::for_value(sid.as_sid()), expected.layout());
    }

    #[test]
    fn stack_mutates_authority_and_existing_values_without_changing_length() {
        let mut sid = stack(&[1, 2]);
        sid.set_identifier_authority(SidIdentifierAuthority::NULL_AUTHORITY);
        let value = sid
            .sub_authorities_mut()
            .get_mut(1)
            .expect("the SID contains two values");
        *value = 42;

        assert_eq!(
            sid.identifier_authority,
            SidIdentifierAuthority::NULL_AUTHORITY
        );
        assert_eq!(sid.sub_authorities(), [1, 42]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn heap_push_extend_pop_and_truncate_keep_exact_layout() {
        let mut sid = heap(&[1]);
        assert_eq!(sid.capacity(), 1);
        assert_logical_heap_layout(&sid);

        sid.try_push_sub_authority(2).expect("capacity remains");
        assert_eq!(sid.sub_authorities(), [1, 2]);
        assert_eq!(sid.capacity(), 2);
        assert_logical_heap_layout(&sid);

        sid.try_extend_sub_authorities([3, 4])
            .expect("capacity remains");
        assert_eq!(sid.sub_authorities(), [1, 2, 3, 4]);
        assert_eq!(sid.capacity(), 4);
        assert_logical_heap_layout(&sid);

        assert_eq!(sid.try_pop_sub_authority(), Ok(4));
        assert_eq!(sid.sub_authorities(), [1, 2, 3]);
        assert_eq!(sid.capacity(), 4);
        assert_logical_heap_layout(&sid);

        sid.try_truncate_sub_authorities(NonZeroUsize::new(1).unwrap())
            .expect("one sub-authority remains");
        assert_eq!(sid.sub_authorities(), [1]);
        assert_eq!(sid.capacity(), 4);
        assert_logical_heap_layout(&sid);

        sid.shrink_to_fit();
        assert_eq!(sid.capacity(), 1);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn heap_try_reserve_reuses_spare_capacity_and_rejects_windows_overflow() {
        let mut sid = heap(&[1, 2]);
        sid.try_reserve(5).expect("seven values fit in a SID");
        let capacity = sid.capacity();
        assert!(capacity >= 7);

        sid.try_extend_sub_authorities([3, 4, 5])
            .expect("reserved capacity is sufficient");
        assert_eq!(sid.capacity(), capacity);

        assert_eq!(
            sid.try_reserve(11),
            Err(ExtendSubAuthoritiesError::TooManySubAuthorities {
                current: 5,
                max: 15,
            })
        );
        assert_eq!(sid.capacity(), capacity);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn heap_reallocates_reuses_and_shrinks_before_drop() {
        let mut sid = heap(&[1]);
        sid.try_reserve(14).expect("the Windows maximum fits");
        assert_eq!(sid.capacity(), 15);
        sid.try_extend_sub_authorities(2..=15)
            .expect("the reserved tail is writable");
        assert_eq!(sid.sub_authorities().len(), 15);

        sid.try_pop_sub_authorities(10)
            .expect("one logical value remains");
        assert_eq!(sid.sub_authorities(), [1, 2, 3, 4, 5]);
        assert_eq!(sid.capacity(), 15);
        sid.try_extend_sub_authorities([16, 17, 18, 19, 20])
            .expect("spare capacity is reused");
        assert_eq!(sid.sub_authorities().len(), 10);

        sid.try_truncate_sub_authorities(NonZeroUsize::new(2).unwrap())
            .expect("the SID remains non-empty");
        sid.shrink_to_fit();
        assert_eq!(sid.capacity(), 2);
        assert_eq!(sid.sub_authorities(), [1, 2]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn heap_clone_from_uses_spare_capacity_and_drops_cleanly() {
        let mut destination = heap(&[10]);
        destination
            .try_reserve(14)
            .expect("the Windows maximum fits");
        let capacity = destination.capacity();
        let source = heap(&[20, 21, 22]);

        destination.clone_from(&source);

        assert_eq!(destination.sub_authorities(), [20, 21, 22]);
        assert_eq!(destination.capacity(), capacity);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn heap_box_roundtrip_shrinks_physical_capacity_before_box_drop() {
        let mut sid = heap(&[7]);
        sid.try_reserve(14).expect("the Windows maximum fits");
        sid.try_extend_sub_authorities([8, 9, 10])
            .expect("reserved capacity is writable");
        sid.try_truncate_sub_authorities(NonZeroUsize::new(2).unwrap())
            .expect("the SID remains non-empty");

        let boxed: Box<crate::Sid> = sid.into();
        assert_eq!(boxed.sub_authorities(), [7, 8]);
        let sid_again: SecurityIdentifier = boxed.into();
        assert_eq!(sid_again.sub_authorities(), [7, 8]);
        assert_eq!(sid_again.capacity(), 2);
    }

    #[test]
    fn stack_extend_overflow_is_transactional() {
        let mut sid = stack(&[1, 2]);
        let before = sid.clone();
        let result = sid.try_extend_sub_authorities(3_u32..=17);

        assert_eq!(
            result,
            Err(ExtendSubAuthoritiesError::TooManySubAuthorities {
                current: 2,
                max: 15,
            })
        );
        assert_eq!(sid, before);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn heap_extend_overflow_is_transactional() {
        let mut sid = heap(&[1, 2]);
        let before = sid.clone();
        let result = sid.try_extend_sub_authorities(3_u32..=17);

        assert_eq!(
            result,
            Err(ExtendSubAuthoritiesError::TooManySubAuthorities {
                current: 2,
                max: 15,
            })
        );
        assert_eq!(sid, before);
        assert_logical_heap_layout(&sid);
    }

    #[test]
    fn push_at_capacity_returns_method_specific_error() {
        let mut sid = stack(&[0; 15]);
        assert_eq!(
            sid.try_push_sub_authority(1),
            Err(PushSubAuthorityError::MaximumSubAuthoritiesReached { max: 15 })
        );
    }

    #[test]
    fn pop_last_returns_method_specific_error() {
        let mut sid = stack(&[1]);
        assert_eq!(
            sid.try_pop_sub_authority(),
            Err(PopSubAuthorityError::CannotRemoveLastSubAuthority)
        );
        assert_eq!(sid.sub_authorities(), [1]);
    }

    #[test]
    fn pop_multiple_returns_owned_slice_and_iterators_in_original_order() {
        let mut sid = stack(&[1, 2, 3, 4]);
        let removed = sid.try_pop_sub_authorities(3).expect("one value remains");

        assert_eq!(removed.as_slice(), [2, 3, 4]);
        assert_eq!(removed.iter().copied().sum::<u32>(), 9);
        assert_eq!(
            removed
                .into_iter()
                .collect::<arrayvec::ArrayVec<u32, 15>>()
                .as_slice(),
            [2, 3, 4]
        );
        assert_eq!(sid.sub_authorities(), [1]);
    }

    #[test]
    fn pop_multiple_overflow_and_empty_truncate_are_transactional() {
        let mut sid = stack(&[1, 2]);
        let before = sid.clone();

        assert_eq!(
            sid.try_pop_sub_authorities(2),
            Err(PopSubAuthoritiesError::InsufficientSubAuthorities {
                requested: 2,
                available: 1,
            })
        );
        assert_eq!(sid, before);
    }

    proptest! {
        #[test]
        fn stack_mutations_match_a_slice_model(
            initial in proptest::collection::vec(any::<u32>(), 1..=15),
            additions in proptest::collection::vec(any::<u32>(), 0..=15),
            requested_pop in 0usize..=15,
        ) {
            let mut sid = stack(&initial);
            let mut model = initial;
            let extend_result = sid.try_extend_sub_authorities(additions.iter().copied());
            if model.len() + additions.len() <= 15 {
                prop_assert_eq!(extend_result, Ok(()));
                model.extend_from_slice(&additions);
            } else {
                prop_assert!(extend_result.is_err());
            }
            prop_assert_eq!(sid.sub_authorities(), model.as_slice());

            let before_pop = model.clone();
            let pop_result = sid.try_pop_sub_authorities(requested_pop);
            if requested_pop < model.len() {
                let split = model.len() - requested_pop;
                let expected = model.split_off(split);
                prop_assert_eq!(pop_result.as_ref().map(PoppedSubAuthorities::as_slice), Ok(expected.as_slice()));
                prop_assert_eq!(sid.sub_authorities(), model.as_slice());
            } else {
                prop_assert!(pop_result.is_err());
                prop_assert_eq!(sid.sub_authorities(), before_pop.as_slice());
            }
        }

        #[cfg(feature = "alloc")]
        #[test]
        fn heap_mutations_match_stack_and_keep_exact_layout(
            initial in proptest::collection::vec(any::<u32>(), 1..=15),
            additions in proptest::collection::vec(any::<u32>(), 0..=15),
            requested_pop in 0usize..=15,
        ) {
            let mut stack_sid = stack(&initial);
            let mut heap_sid = heap(&initial);

            let stack_extend = stack_sid.try_extend_sub_authorities(additions.iter().copied());
            let heap_extend = heap_sid.try_extend_sub_authorities(additions.iter().copied());
            prop_assert_eq!(stack_extend, heap_extend);
            prop_assert_eq!(stack_sid.as_sid(), heap_sid.as_sid());
            assert_logical_heap_layout(&heap_sid);

            let stack_pop = stack_sid.try_pop_sub_authorities(requested_pop);
            let heap_pop = heap_sid.try_pop_sub_authorities(requested_pop);
            prop_assert_eq!(stack_pop, heap_pop);
            prop_assert_eq!(stack_sid.as_sid(), heap_sid.as_sid());
            assert_logical_heap_layout(&heap_sid);
        }
    }
}
