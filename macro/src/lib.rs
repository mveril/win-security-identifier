#![allow(
    clippy::missing_inline_in_public_items,
    reason = "Not an issue in a macro crate"
)]
//! Procedural macro for compile-time Windows Security Identifier (SID) parsing.
mod core;
use core::sid_impl;
use proc_macro::TokenStream;

use syn::{LitStr, parse_macro_input};

#[proc_macro]
pub fn sid(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    match sid_impl(&lit) {
        Ok(token_stream) => token_stream,
        Err(err) => err.to_compile_error(),
    }
    .into()
}
