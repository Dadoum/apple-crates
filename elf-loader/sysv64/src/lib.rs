use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, Signature, TypeBareFn};

#[proc_macro_attribute]
pub fn sysv64(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let ItemFn {
        attrs,
        vis,
        sig:
            Signature {
                constness,
                asyncness,
                unsafety,
                abi: _,
                fn_token,
                ident,
                generics,
                paren_token: _,
                inputs,
                variadic,
                output,
            },
        block,
    } = parse_macro_input!(item as ItemFn);

    quote! {
        #[cfg(target_arch = "x86_64")]
        #(#attrs)*
        #vis #constness #asyncness #unsafety extern "sysv64" #fn_token #ident #generics (#inputs) #variadic #output #block

        #[cfg(not(target_arch = "x86_64"))]
        #(#attrs)*
        #vis #constness #asyncness #unsafety extern "C" #fn_token #ident #generics (#inputs) #variadic #output #block
    }.into()
}
