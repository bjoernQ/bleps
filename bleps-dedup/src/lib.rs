use proc_macro::{Delimiter, TokenStream};
use proc_macro_error::proc_macro_error;

#[derive(Debug)]
struct Implementation {
    is_async: bool,
    tokens: TokenStream,
}

/// A macro to de-duplicate SYNC / ASYNC code loosely inspired by maybe-async
#[proc_macro]
#[proc_macro_error]
pub fn dedup(input: TokenStream) -> TokenStream {
    let mut impls: Vec<Implementation> = Vec::new();
    let mut body = None;
    let mut impl_is_async = false;

    let mut current = TokenStream::new();
    for token in input.into_iter() {
        let tok = token.clone();
        match token {
            proc_macro::TokenTree::Ident(ident) => match ident.to_string().as_str() {
                "impl" => {
                    if !current.is_empty() {
                        impls.push(Implementation {
                            is_async: impl_is_async,
                            tokens: current,
                        })
                    }
                    current = TokenStream::new();
                    current.extend([tok]);
                }
                "SYNC" => {
                    impl_is_async = false;
                }
                "ASYNC" => {
                    impl_is_async = true;
                }
                _ => {
                    current.extend([tok]);
                }
            },
            proc_macro::TokenTree::Group(group) if group.delimiter() == Delimiter::Brace => {
                if !current.is_empty() {
                    impls.push(Implementation {
                        is_async: impl_is_async,
                        tokens: current.clone(),
                    })
                }

                let mut stream = TokenStream::new();
                stream.extend([tok]);
                body = Some(stream);
            }
            _ => {
                current.extend([tok]);
            }
        }
    }

    let mut generated = Vec::new();
    for imp in impls {
        #[cfg(not(feature = "generate-async"))]
        if imp.is_async {
            continue;
        }

        let decl: proc_macro2::TokenStream = imp.tokens.into();
        let block: proc_macro2::TokenStream = if !imp.is_async {
            de_async(body.clone().unwrap().into())
        } else {
            body.clone().unwrap().into()
        };

        generated.push(quote::quote!(
            #decl
            #block
        ));
    }

    quote::quote!(
        #(#generated)*
    )
    .into()
}

fn de_async(input: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    let mut output = proc_macro2::TokenStream::new();

    let mut prev = None;
    for token in input.into_iter() {
        let tok = token.clone();
        match token {
            proc_macro2::TokenTree::Ident(ident) => {
                if match ident.to_string().as_str() {
                    "await" => {
                        prev = None;
                        false
                    }
                    "async" => false,
                    _ => true,
                } {
                    if let Some(prev) = prev.clone() {
                        output.extend([prev]);
                    }
                    prev = None;
                    output.extend([tok]);
                }
            }
            proc_macro2::TokenTree::Punct(p) => {
                if p.as_char() == '.' {
                    if let Some(prev) = prev.clone() {
                        output.extend([prev]);
                    }
                    prev = Some(tok);
                } else {
                    if let Some(prev) = prev.clone() {
                        output.extend([prev]);
                    }
                    prev = None;

                    output.extend([tok]);
                }
            }
            proc_macro2::TokenTree::Group(group) => {
                if let Some(prev) = prev.clone() {
                    output.extend([prev]);
                }
                prev = None;

                let converted = de_async(group.stream());
                let group = proc_macro2::Group::new(group.delimiter(), converted);
                let group = proc_macro2::TokenTree::Group(group);
                output.extend([group]);
            }
            _ => {
                if let Some(prev) = prev.clone() {
                    output.extend([prev]);
                }
                prev = None;
                output.extend([tok]);
            }
        }
    }

    if let Some(prev) = prev.clone() {
        output.extend([prev]);
    }

    output
}
