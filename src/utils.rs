use core::mem::offset_of;
use core::{borrow::Borrow, fmt};

use crate::{
    InvalidSidBinaryFormat, Sid, SidSizeInfo,
    sid::{MAX_SUBAUTHORITY_COUNT, MIN_SUBAUTHORITY_COUNT},
};

pub const fn sub_authority_size_guard(size: usize) -> bool {
    MIN_SUBAUTHORITY_COUNT as usize <= size && size <= MAX_SUBAUTHORITY_COUNT as usize
}

/// Validates a raw SID blob like `IsValidSid` would, without assuming alignment.
pub const fn validate_sid_bytes_unaligned(buf: &[u8]) -> Result<(), InvalidSidBinaryFormat> {
    const REVISION_OFFSET: usize = offset_of!(Sid, revision);
    const COUNT_OFFSET: usize = offset_of!(Sid, sub_authority_count);
    const MIN_SIZE: usize = SidSizeInfo::MIN.layout().size();
    if buf.len() < MIN_SIZE {
        return Err(InvalidSidBinaryFormat::TooShort {
            len: buf.len(),
            min_len: MIN_SIZE,
        });
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "We know the revision_offset is in the bound (was checked by minimum size)"
    )]
    let revision = buf[REVISION_OFFSET];
    if revision != Sid::REVISION {
        return Err(InvalidSidBinaryFormat::InvalidRevision {
            revision,
            expected: Sid::REVISION,
        });
    }
    #[expect(
        clippy::indexing_slicing,
        reason = "We know the count_offset is in the bound (was checked by minimum size)"
    )]
    let count = buf[COUNT_OFFSET];

    if !sub_authority_size_guard(count as usize) {
        return Err(InvalidSidBinaryFormat::InvalidSubAuthorityCount {
            count,
            min: MIN_SUBAUTHORITY_COUNT,
            max: MAX_SUBAUTHORITY_COUNT,
        });
    }

    // SAFETY: size already validated
    let size = unsafe { SidSizeInfo::from_count(count).unwrap_unchecked() }
        .layout()
        .size();

    if buf.len() != size {
        return Err(InvalidSidBinaryFormat::InvalidLength {
            len: buf.len(),
            expected_len: size,
            count,
        });
    }

    Ok(())
}

#[expect(
    clippy::inline_always,
    reason = "It is used only one time for each file."
)]
#[inline(always)]
pub fn debug_print<T: Borrow<Sid> + ?Sized>(
    struct_name: &str,
    sid: &T,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    let sid = sid.borrow();
    if f.alternate() {
        f.debug_struct(struct_name)
            .field("revision", &sid.revision)
            .field("sub_authority_count", &sid.sub_authority_count)
            .field("identifier_authority", &sid.identifier_authority)
            .field("sub_authority", &sid.sub_authorities())
            .finish()
    } else {
        write!(f, "{struct_name}({sid})")
    }
}

#[allow(clippy::expect_used, clippy::indexing_slicing)]
#[cfg(test)]
mod test {
    use super::*;
    use arrayvec::ArrayVec;
    use core::iter::repeat_n;
    use proptest::prelude::*;
    const MIN_SIZE: usize = SidSizeInfo::MIN.layout().size();
    const MAX_SIZE: usize = SidSizeInfo::MAX.layout().size();
    const TEST_BUF_SIZE: usize = MAX_SIZE + 7;
    const REVISION_OFFSET: usize = offset_of!(Sid, revision);
    const COUNT_OFFSET: usize = offset_of!(Sid, sub_authority_count);

    /// Builds a raw SID buffer for the given sub-authority count.
    fn make_sid_bytes(count: u8) -> ArrayVec<u8, TEST_BUF_SIZE> {
        assert!(
            sub_authority_size_guard(count as usize),
            "Invalid count for make_sid_bytes()"
        );

        let layout = SidSizeInfo::from_count(count)
            .expect("valid count")
            .layout();

        let mut buf: ArrayVec<u8, TEST_BUF_SIZE> = ArrayVec::new();
        buf.extend(repeat_n(0, layout.size()));
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
            let mut buf = ArrayVec::<u8, MIN_SIZE>::new();
            buf.extend(repeat_n(0, len));
            if let Some(first) = buf.first_mut() {
                *first = 1;
            }

            assert_eq!(
                validate_sid_bytes_unaligned(&buf),
                Err(InvalidSidBinaryFormat::TooShort {
                    len,
                    min_len: MIN_SIZE
                })
            );
        }
    }

    #[test]
    fn rejects_zero_sub_authority() {
        let mut buf = make_sid_bytes(1);
        let count_offset = offset_of!(Sid, sub_authority_count);
        buf[count_offset] = 0;

        assert_eq!(
            validate_sid_bytes_unaligned(&buf),
            Err(InvalidSidBinaryFormat::InvalidSubAuthorityCount {
                count: 0,
                min: MIN_SUBAUTHORITY_COUNT,
                max: MAX_SUBAUTHORITY_COUNT,
            })
        );
    }

    #[test]
    fn rejects_excessive_sub_authority() {
        let mut buf = make_sid_bytes(1);

        let count_offset = offset_of!(Sid, sub_authority_count);
        buf[count_offset] = MAX_SUBAUTHORITY_COUNT + 1;

        assert_eq!(
            validate_sid_bytes_unaligned(&buf),
            Err(InvalidSidBinaryFormat::InvalidSubAuthorityCount {
                count: MAX_SUBAUTHORITY_COUNT + 1,
                min: MIN_SUBAUTHORITY_COUNT,
                max: MAX_SUBAUTHORITY_COUNT,
            })
        );
    }

    #[test]
    fn rejects_wrong_size_for_count() {
        let mut buf = make_sid_bytes(1);
        let count_offset = offset_of!(Sid, sub_authority_count);
        buf[count_offset] = 2;

        assert_eq!(
            validate_sid_bytes_unaligned(&buf),
            Err(InvalidSidBinaryFormat::InvalidLength {
                len: SidSizeInfo::MIN.layout().size(),
                expected_len: SidSizeInfo::from_count(2)
                    .expect("valid count")
                    .layout()
                    .size(),
                count: 2,
            })
        );
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
            let mut buf = ArrayVec::<u8, MIN_SIZE>::new();
            buf.extend(repeat_n(0, len));
            prop_assert_eq!(
                validate_sid_bytes_unaligned(&buf),
                Err(InvalidSidBinaryFormat::TooShort { len, min_len: MIN_SIZE })
            );
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
                buf.extend(repeat_n(0, extra));
            }

            let expected = if buf.len() < MIN_SIZE {
                InvalidSidBinaryFormat::TooShort {
                    len: buf.len(),
                    min_len: MIN_SIZE,
                }
            } else {
                InvalidSidBinaryFormat::InvalidLength {
                    len: buf.len(),
                    expected_len: SidSizeInfo::from_count(count).expect("valid count").layout().size(),
                    count,
                }
            };

            prop_assert_eq!(validate_sid_bytes_unaligned(&buf), Err(expected));
        }
        #[test]
        fn proptest_wrong_revision_is_rejected(revision in prop_oneof![Just(0u8), 2u8..], count in MIN_SUBAUTHORITY_COUNT..=MAX_SUBAUTHORITY_COUNT){
            let mut buf =make_sid_bytes(count);
            buf[REVISION_OFFSET] = revision;
            prop_assert_eq!(
                validate_sid_bytes_unaligned(&buf),
                Err(InvalidSidBinaryFormat::InvalidRevision {
                    revision,
                    expected: Sid::REVISION,
                })
            );
        }

        #[test]
        fn proptest_public_from_bytes_return_binary_errors(revision in prop_oneof![Just(0u8), 2u8..], count in MIN_SUBAUTHORITY_COUNT..=MAX_SUBAUTHORITY_COUNT) {
            let sub_authorities = [0u32; MAX_SUBAUTHORITY_COUNT as usize];
            let mut stack_sid = crate::StackSid::try_new(
                crate::SidIdentifierAuthority::NT_AUTHORITY,
                &sub_authorities[..count as usize],
            )
            .expect("valid sub-authority count");
            let buf = unsafe {
                // SAFETY: The bytes come from `StackSid`, so the buffer is aligned for `Sid`.
                // The test mutates only the revision byte while preserving allocation and length.
                let bytes = stack_sid.as_bytes_mut();
                bytes[REVISION_OFFSET] = revision;
                bytes
            };
            let expected = InvalidSidBinaryFormat::InvalidRevision {
                revision,
                expected: Sid::REVISION,
            };

            prop_assert_eq!(
                crate::StackSid::from_bytes(buf),
                Err(expected)
            );

            #[cfg(feature = "alloc")]
            prop_assert_eq!(
                crate::SecurityIdentifier::from_bytes(buf).err(),
                Some(expected)
            );

            let sid = unsafe {
                // SAFETY: `buf` points into `stack_sid`, whose storage is aligned for `Sid`.
                Sid::from_bytes(buf)
            };
            prop_assert_eq!(sid.err(), Some(expected));
        }
    }
}
