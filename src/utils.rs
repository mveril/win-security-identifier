pub const fn sub_authority_size_guard(size: usize) -> bool {
    size != 0 && size < 16
}
