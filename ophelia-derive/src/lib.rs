extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{self, DeriveInput};

#[proc_macro_derive(SecretDebug)]
pub fn secret_debug(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).expect("Should parse code to impl secret debug");
    let name = &ast.ident;

    let gen = quote! {
        impl std::fmt::Debug for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "secret {}", stringify!(#name))
            }
        }
    };

    gen.into()
}
