use crate::sid::{MAX_SUBAUTHORITY_COUNT, MIN_SUBAUTHORITY_COUNT, SID_HEAD_SIZE, SidHead};
use crate::utils::sub_authority_size_guard;
use core::alloc::Layout;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        if Self::MIN.get_layout().size() > size || size > Self::MAX.get_layout().size() {
            return None;
        }

        // Remaining must be multiple of u32
        let remaining = size - SID_HEAD_SIZE;
        if remaining % core::mem::size_of::<u32>() != 0 {
            return None;
        }

        // Number of sub-authorities
        let sub_authority_count = (remaining / core::mem::size_of::<u32>()) as u8;

        // Delegate to guard
        Self::from_count(sub_authority_count)
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
    use proptest::prelude::*;

    use core::mem::size_of;
    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn prop_full_size_and_from_full_size(sub_authority_count in 0u8..16) {
            let info = SidSizeInfo::from_count(sub_authority_count).unwrap();
            let size = info.get_layout().size();
            let reconstructed = SidSizeInfo::from_full_size(size);
            prop_assert_eq!(info.sub_authority_count, reconstructed.unwrap().get_sub_authority_count());
        }

        #[test]
        fn prop_layout_properties(sub_authority_count in 0u8..16) {
            let info = SidSizeInfo::from_count(sub_authority_count).unwrap();
            let layout = info.get_layout();
            let expected_align = align_of::<u32>();
            prop_assert_eq!(layout.size(), SID_HEAD_SIZE + (info.sub_authority_count as usize) * size_of::<u32>());
            prop_assert_eq!(layout.align(), expected_align);
        }

        #[test]
        fn prop_full_size_always_multiple_of_u32(sub_authority_count in 0u8..16) {
            let info = SidSizeInfo::from_count(sub_authority_count).unwrap();
            let size = info.get_layout().size();
            prop_assert!((size - SID_HEAD_SIZE) % size_of::<u32>() == 0);
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
            fn test_prop_full_size_compare_windows(sub_authority_count in 0u8..16) {
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
