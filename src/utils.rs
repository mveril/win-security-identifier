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
///
/// - `sub_authority_count` in [1..=15]
/// - total size == 8 + 4 * `sub_authority_count`
/// - identifier authority is 6 bytes (big-endian); any value is accepted
///
/// No references to possibly-unaligned typed fields are created.
/// Everything is read from bytes using unaligned-safe operations.
pub const fn validate_sid_bytes_unaligned(buf: &[u8]) -> Result<(), InvalidSidFormat> {
    const REVISION_OFFSET: usize = offset_of!(Sid, revision);
    const COUNT_OFFSET: usize = offset_of!(Sid, sub_authority_count);
    let min_size = SidSizeInfo::MIN.get_layout().size();
    if buf.len() < min_size {
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
    // SAFETY: Size already checked previously
    let size = unsafe { SidSizeInfo::from_count(count).unwrap_unchecked() }
        .get_layout()
        .size();
    if buf.len() != size {
        return Err(InvalidSidFormat);
    }
    Ok(())
}
