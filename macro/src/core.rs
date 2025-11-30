use parsing::SidComponents;
use proc_macro_crate::{Error as MacroCrateError, FoundCrate, crate_name};
use proc_macro2::TokenStream;
use quote::quote;
use syn::LitStr;

pub fn sid_impl(input: &LitStr) -> Result<TokenStream, syn::Error> {
    let components: SidComponents = input
        .value()
        .parse()
        .map_err(|e| syn::Error::new_spanned(input, e))?;
    let authority = components.identifier_authority;
    let sub_authority = components.sub_authority.as_slice();
    let len = sub_authority.len();
    let root = crate_root("win-security-identifier").map_err(|err| {
        syn::Error::new(
            proc_macro2::Span::call_site(),
            format!("Root crate not found:{err}"),
        )
    })?;

    let expanded = quote! {
        #root::ConstSid::<#len>::new(
            [#(#authority),*].into(),
            [#(#sub_authority),*]
        )
    };
    Ok(expanded)
}

fn crate_root(name: &str) -> Result<TokenStream, MacroCrateError> {
    crate_name(name).map(|found| match found {
        FoundCrate::Name(found_name) => {
            let ident = syn::Ident::new(&found_name, proc_macro2::Span::call_site());
            quote!(::#ident)
        }
        FoundCrate::Itself => quote!(crate),
    })
}
