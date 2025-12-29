use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, Signature, TypeBareFn};

#[proc_macro_attribute]
pub fn sysv64(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let arch = env!("TARGET_ARCH");

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

    if arch == "x86_64" {
        quote! {
            #(#attrs)*
            #vis #constness #asyncness #unsafety extern "sysv64" #fn_token #ident #generics (#inputs) #variadic #output #block
        }
    } else {
        quote! {
            #(#attrs)*
            #vis #constness #asyncness #unsafety extern "C" #fn_token #ident #generics (#inputs) #variadic #output #block
        }
    }.into()
}

#[proc_macro]
pub fn sysv64_type(input: TokenStream) -> TokenStream {
    let arch = env!("TARGET_ARCH");

    let TypeBareFn {
        lifetimes: _,
        unsafety,
        abi: _,
        fn_token,
        paren_token: _,
        inputs,
        variadic,
        output,
    } = parse_macro_input!(input as TypeBareFn);

    if arch == "x86_64" {
        quote! {
            #unsafety extern "sysv64" #fn_token (#inputs) #variadic #output
        }
    } else {
        quote! {
            #unsafety extern "C" #fn_token (#inputs) #variadic #output
        }
    }
    .into()
}
