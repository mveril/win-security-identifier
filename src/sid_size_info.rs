#[cfg(feature = "alloc")]
use crate::sid::SID_HEAD_SIZE;
use crate::sid::{MAX_SUBAUTHORITY_COUNT, MIN_SUBAUTHORITY_COUNT, SidHead};
use crate::utils::sub_authority_size_guard;
use core::alloc::Layout;

#[derive(PartialEq, Debug, Eq, PartialOrd, Ord, Hash)]
pub struct SidSizeInfo {
    sub_authority_count: u8,
}

impl SidSizeInfo {
    // Safety: `MIN_SUBAUTHORITY_COUNT` is known to be valid.
    pub const MIN: Self = unsafe { Self::from_count(MIN_SUBAUTHORITY_COUNT).unwrap_unchecked() };
    // Safety: `MAX_SUBAUTHORITY_COUNT` is known to be valid.
    #[allow(dead_code)]
    pub const MAX: Self = unsafe { Self::from_count(MAX_SUBAUTHORITY_COUNT).unwrap_unchecked() };

    pub const fn from_count(sub_authority_count: u8) -> Option<Self> {
        if sub_authority_size_guard(sub_authority_count as usize) {
            Some(Self {
                sub_authority_count,
            })
        } else {
            None
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub const fn get_sub_authority_count(self) -> u8 {
        self.sub_authority_count
    }

    #[cfg(feature = "alloc")]
    /// Try to reconstruct a [`SidSizeInfo`] from the full size in bytes
    /// of a SID structure (head + sub-authorities).
    ///
    /// Returns `None` if the size is invalid.
    #[allow(dead_code, reason = "useful method even if not used at this point")]
    pub const fn from_full_size(size: usize) -> Option<Self> {
        const MIN_SIZE: usize = SidSizeInfo::MIN.get_layout().size();
        const MAX_SIZE: usize = SidSizeInfo::MAX.get_layout().size();
        if MAX_SIZE < size || size < MIN_SIZE {
            return None;
        }

        // Remaining must be multiple of u32
        let remaining = size - SID_HEAD_SIZE;
        if !remaining.is_multiple_of(core::mem::size_of::<u32>()) {
            return None;
        }

        // Number of sub-authorities
        #[expect(clippy::integer_division, reason = "checked to be multiple of u32")]
        let sub_authority_count = remaining / core::mem::size_of::<u32>();
        // Delegate to guard
        #[expect(
            clippy::cast_possible_truncation,
            reason = "sub_authority_count is checked to be in the correct bounds"
        )]
        Self::from_count(sub_authority_count as u8)
    }

    pub const fn get_layout(&self) -> Layout {
        let head: Layout = Layout::new::<SidHead>();
        let Ok(dyn_layout) = Layout::array::<u32>(self.sub_authority_count as usize) else {
            unreachable!()
        };
        if let Ok((l, _)) = head.extend(dyn_layout) {
            l.pad_to_align()
        } else {
            unreachable!()
        }
    }
}
#[allow(clippy::unwrap_used, reason = "Unwrap is not an issue in test")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::ConstSid;
    use proptest::prelude::*;

    use core::mem::size_of;

    /// Macro to generate all `size_of::<ConstSid<N>>()` for N = 1..16.
    macro_rules! all_sizes {
    ($($n:literal),*) => {
        [ $( size_of::<ConstSid<$n>>()),* ]
    };
}

    /// All valid sizes for `ConstSid<N>` (N = 1..16).
    const ALL_SIZES: [usize; 15] = all_sizes!(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    /// Strategy generating only *invalid* sizes (u8 not in `ALL_SIZES`).
    fn arb_invalid_size() -> impl Strategy<Value = usize> {
        (0usize..=u8::MAX as usize)
            .prop_filter("must not be a valid size", |n| !ALL_SIZES.contains(n))
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn prop_full_size_and_from_full_size(sub_authority_count in MIN_SUBAUTHORITY_COUNT..=MAX_SUBAUTHORITY_COUNT) {
            let info = SidSizeInfo::from_count(sub_authority_count).unwrap();
            let size = info.get_layout().size();
            let reconstructed = SidSizeInfo::from_full_size(size);
            prop_assert_eq!(info, reconstructed.unwrap());
        }

        #[test]
        fn prop_layout_properties(sub_authority_count in MIN_SUBAUTHORITY_COUNT..=MAX_SUBAUTHORITY_COUNT) {
            let info = SidSizeInfo::from_count(sub_authority_count).unwrap();
            let layout = info.get_layout();
            let expected_align = align_of::<u32>();
            prop_assert_eq!(layout.size(), SID_HEAD_SIZE + (info.sub_authority_count as usize) * size_of::<u32>());
            prop_assert_eq!(layout.align(), expected_align);
        }

        #[test]
        fn prop_full_size_always_multiple_of_u32(sub_authority_count in  prop_oneof![
        (0u8..MIN_SUBAUTHORITY_COUNT),
        ((MAX_SUBAUTHORITY_COUNT+1)..=u8::MAX),
    ]) {
            let info = SidSizeInfo::from_count(sub_authority_count);
            prop_assert!(info.is_none());
        }

        #[test]
        fn prop_invalid_size_return_none(size in  arb_invalid_size()){
            prop_assert_eq!(SidSizeInfo::from_full_size(size), None);
        }

        #[test]
        fn prop_valid_size_return_some(size in  prop::sample::select(&ALL_SIZES)){
            prop_assert_eq!(SidSizeInfo::from_full_size(size), None);
        }
    }
    #[cfg(windows)]
    mod windows {
        use super::super::*;
        use proptest::prelude::*;
        use windows_sys::Win32::Security::*;

        #[test]
        fn test_layout_matches_windows_sid() {
            // Par convention, un SID Windows "classique" a 1 sub-authority.
            let info = SidSizeInfo::from_count(1).unwrap();
            assert_eq!(Layout::new::<SID>(), info.get_layout());
        }
        #[cfg(feature = "std")]
        proptest! {
            #[test]
            fn test_prop_full_size_compare_windows(sub_authority_count in MIN_SUBAUTHORITY_COUNT..=MAX_SUBAUTHORITY_COUNT) {
                let info = SidSizeInfo::from_count(sub_authority_count ).unwrap();
                let size = info.get_layout().size();
                let winsize = unsafe {
                    GetSidLengthRequired(sub_authority_count)
                } as usize;
                prop_assert!(size == winsize );
            }
        }
    }
}
