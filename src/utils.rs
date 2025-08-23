use crate::sid::{MAX_SUBAUTHORITY_COUNT, MIN_SUBAUTHORITY_COUNT};

pub const fn sub_authority_size_guard(size: usize) -> bool {
    MIN_SUBAUTHORITY_COUNT as usize <= size && size <= MAX_SUBAUTHORITY_COUNT as usize
}
