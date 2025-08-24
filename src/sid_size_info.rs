use crate::sid::{MAX_SUBAUTHORITY_COUNT, MIN_SUBAUTHORITY_COUNT, SID_HEAD_SIZE, SidHead};
use crate::utils::sub_authority_size_guard;
use core::alloc::Layout;

#[derive(PartialEq, Debug, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SidSizeInfo {
    sub_authority_count: u8,
}

impl SidSizeInfo {
    pub const MIN: SidSizeInfo =
        unsafe { SidSizeInfo::from_count(MIN_SUBAUTHORITY_COUNT).unwrap_unchecked() };
    pub const MAX: SidSizeInfo =
        unsafe { SidSizeInfo::from_count(MAX_SUBAUTHORITY_COUNT).unwrap_unchecked() };

    pub const fn from_count(sub_authority_count: u8) -> Option<SidSizeInfo> {
        if sub_authority_size_guard(sub_authority_count as usize) {
            Some(Self {
                sub_authority_count: sub_authority_count,
            })
        } else {
            None
        }
    }

    #[inline(always)]
    pub const fn get_sub_authority_count(self) -> u8 {
        self.sub_authority_count
    }

    #[cfg(feature = "alloc")]
    /// Try to reconstruct a [`SidSizeInfo`] from the full size in bytes
    /// of a SID structure (head + sub-authorities).
    ///
    /// Returns `None` if the size is invalid.
    pub const fn from_full_size(size: usize) -> Option<Self> {
        if SID_HEAD_SIZE > size {
            return None;
        }

        // Remaining must be multiple of u32
        let remaining = size - SID_HEAD_SIZE;
        if remaining % core::mem::size_of::<u32>() != 0 {
            return None;
        }

        // Number of sub-authorities
        let sub_authority_count = (remaining / core::mem::size_of::<u32>());
        if sub_authority_count > u8::MAX as usize {
            return None;
        }
        // Delegate to guard
        Self::from_count(sub_authority_count as u8)
    }

    pub const fn get_layout(&self) -> Layout {
        let head: Layout = Layout::new::<SidHead>();
        let dyn_layout = match Layout::array::<u32>(self.sub_authority_count as usize) {
            Ok(l) => l,
            Err(_) => unreachable!(),
        };
        match head.extend(dyn_layout) {
            Ok((l, _)) => l.pad_to_align(),
            Err(_) => unreachable!(),
        }
    }
}

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
            prop_assert!(SidSizeInfo::from_full_size(size).is_none())
        }

        #[test]
        fn prop_valid_size_return_some(size in  prop::sample::select(&ALL_SIZES)){
            prop_assert!(SidSizeInfo::from_full_size(size).is_some())
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
