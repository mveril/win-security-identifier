use core::mem::offset_of;

use parsing::InvalidSidFormat;

use crate::{
    Sid, SidSizeInfo,
    sid::{MAX_SUBAUTHORITY_COUNT, MIN_SUBAUTHORITY_COUNT},
};

pub const fn sub_authority_size_guard(size: usize) -> bool {
    MIN_SUBAUTHORITY_COUNT as usize <= size && size <= MAX_SUBAUTHORITY_COUNT as usize
}

/// Validates a raw SID blob like `IsValidSid` would, without assuming alignment.
pub const fn validate_sid_bytes_unaligned(buf: &[u8]) -> Result<(), InvalidSidFormat> {
    const REVISION_OFFSET: usize = offset_of!(Sid, revision);
    const COUNT_OFFSET: usize = offset_of!(Sid, sub_authority_count);
    const MIN_SIZE: usize = SidSizeInfo::MIN.get_layout().size();
    if buf.len() < MIN_SIZE {
        return Err(InvalidSidFormat);
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "We know the revision_offset is in the bound (was checked by minimum size)"
    )]
    if buf[REVISION_OFFSET] != Sid::REVISION {
        return Err(InvalidSidFormat);
    }
    #[expect(
        clippy::indexing_slicing,
        reason = "We know the count_offset is in the bound (was checked by minimum size)"
    )]
    let count = buf[COUNT_OFFSET];

    if !sub_authority_size_guard(count as usize) {
        return Err(InvalidSidFormat);
    }

    // SAFETY: size already validated
    let size = unsafe { SidSizeInfo::from_count(count).unwrap_unchecked() }
        .get_layout()
        .size();

    if buf.len() != size {
        return Err(InvalidSidFormat);
    }

    Ok(())
}

#[allow(clippy::expect_used, clippy::indexing_slicing)]
#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;
    const MIN_SIZE: usize = SidSizeInfo::MIN.get_layout().size();
    const REVISION_OFFSET: usize = offset_of!(Sid, revision);
    const COUNT_OFFSET: usize = offset_of!(Sid, sub_authority_count);

    /// Builds a raw SID buffer for the given sub-authority count.
    fn make_sid_bytes(count: u8) -> Vec<u8> {
        assert!(
            sub_authority_size_guard(count as usize),
            "Invalid count for make_sid_bytes()"
        );

        let layout = SidSizeInfo::from_count(count)
            .expect("valid count")
            .get_layout();

        let mut buf = vec![0u8; layout.size()];
        buf[REVISION_OFFSET] = Sid::REVISION;
        buf[COUNT_OFFSET] = count;
        buf
    }

    // -------------------------------------------------------------
    // Basic tests
    // -------------------------------------------------------------

    #[test]
    fn rejects_too_small_buffer() {
        for len in 0..MIN_SIZE {
            let mut buf = vec![0u8; len];
            if let Some(first) = buf.first_mut() {
                *first = 1;
            }

            assert_eq!(validate_sid_bytes_unaligned(&buf), Err(InvalidSidFormat));
        }
    }

    #[test]
    fn rejects_zero_sub_authority() {
        let mut buf = make_sid_bytes(1);
        let count_offset = offset_of!(Sid, sub_authority_count);
        buf[count_offset] = 0;

        assert_eq!(validate_sid_bytes_unaligned(&buf), Err(InvalidSidFormat));
    }

    #[test]
    fn rejects_excessive_sub_authority() {
        let mut buf = vec![0u8; MIN_SIZE];

        let count_offset = offset_of!(Sid, sub_authority_count);
        buf[count_offset] = MAX_SUBAUTHORITY_COUNT + 1;

        assert_eq!(validate_sid_bytes_unaligned(&buf), Err(InvalidSidFormat));
    }

    #[test]
    fn rejects_wrong_size_for_count() {
        let mut buf = make_sid_bytes(1);
        let count_offset = offset_of!(Sid, sub_authority_count);
        buf[count_offset] = 2;

        assert_eq!(validate_sid_bytes_unaligned(&buf), Err(InvalidSidFormat));
    }

    #[test]
    fn accepts_all_valid_counts() {
        for count in MIN_SUBAUTHORITY_COUNT..=MAX_SUBAUTHORITY_COUNT {
            let buf = make_sid_bytes(count);
            assert_eq!(validate_sid_bytes_unaligned(&buf), Ok(()));
        }
    }

    // -------------------------------------------------------------
    // proptest for the guard (your tests)
    // -------------------------------------------------------------

    proptest! {
        #[test]
        fn guard_ok(count in (1_usize..=15_usize)){
            prop_assert!(sub_authority_size_guard(count));
        }

        #[test]
        fn guard_err(count in (16_usize..)){
            prop_assert!(!sub_authority_size_guard(count));
        }
    }

    // -------------------------------------------------------------
    // Additional proptest validations
    // -------------------------------------------------------------

    proptest! {
        #[test]
        fn proptest_valid_sids_are_accepted(count in MIN_SUBAUTHORITY_COUNT..=MAX_SUBAUTHORITY_COUNT) {
            let buf = make_sid_bytes(count);
            prop_assert_eq!(validate_sid_bytes_unaligned(&buf), Ok(()));
        }

        #[test]
        fn proptest_short_buffers_are_rejected(len in 0usize..MIN_SIZE) {
            let buf = vec![0u8; len];
            prop_assert_eq!(validate_sid_bytes_unaligned(&buf), Err(InvalidSidFormat));
        }

        #[test]
        fn proptest_wrong_length_is_rejected(
            count in MIN_SUBAUTHORITY_COUNT..=MAX_SUBAUTHORITY_COUNT,
            extra in 1usize..8usize
        ) {
            let mut buf = make_sid_bytes(count);

            if extra % 2 == 0 {
                buf.truncate(buf.len().saturating_sub(extra));
            } else {
                buf.extend(core::iter::repeat_n(0u8, extra));
            }

            prop_assert_eq!(validate_sid_bytes_unaligned(&buf), Err(InvalidSidFormat));
        }
        #[test]
        fn proptest_wrong_revision_is_rejected(revision in prop_oneof![Just(0u8), 2u8..], count in MIN_SUBAUTHORITY_COUNT..=MAX_SUBAUTHORITY_COUNT){
            let mut buf =make_sid_bytes(count);
            buf[REVISION_OFFSET] = revision;
            prop_assert_eq!(validate_sid_bytes_unaligned(&buf), Err(InvalidSidFormat));
        }
    }
}
