pub trait SidLenValid {}
macro_rules! impl_valid {
    ($($n:literal),* $(,)?) => { $( impl SidLenValid for [u32; $n] {} )* };
}
impl_valid!(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
