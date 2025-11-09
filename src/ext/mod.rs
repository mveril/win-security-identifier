#[cfg(all(windows, feature = "std"))]
mod windows;
#[cfg(all(windows, feature = "std"))]
pub use windows::{GetCurrentSid, TokenError};
