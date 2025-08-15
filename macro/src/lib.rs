use parsing::{InvalidSidFormat, SidComponents};
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote_spanned;
use syn::{LitStr, parse_macro_input};
mod core;
use core::sid_impl;

#[proc_macro]
pub fn sid(input: TokenStream) -> TokenStream {
    // Lecture du littéral string
    let lit = parse_macro_input!(input as LitStr);
    match sid_impl(&lit) {
        Ok(token_stream) => token_stream,
        Err(err) => err.to_compile_error(),
    }
    .into()
}
