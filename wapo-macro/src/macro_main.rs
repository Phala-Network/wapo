use proc_macro2::TokenStream;

pub(crate) fn patch(input: TokenStream) -> TokenStream {
    match patch_or_err(input) {
        Ok(tokens) => tokens,
        Err(err) => err.to_compile_error(),
    }
}

fn patch_or_err(input: TokenStream) -> syn::Result<TokenStream> {
    let main_fn: syn::ItemFn = syn::parse2(input.clone())?;
    let main_ident = &main_fn.sig.ident;
    let crate_wapo = crate::find_crate_name("wapo")?;
    Ok(syn::parse_quote! {
        #[no_mangle]
        extern "C" fn __main_argc_argv(_: i32, _: i32) -> i32 {
            0
        }
        #[no_mangle]
        extern "C" fn wapo_poll() -> i32 {
            #crate_wapo::env::tasks::wapo_poll()
        }
        #[no_mangle]
        fn wapo_main_future() -> std::pin::Pin<std::boxed::Box<dyn std::future::Future<Output = ()>>> {
            use core::fmt::Debug;

            trait MaybeError {
                type Error: Debug;
                fn into_error(self) -> Option<Self::Error>;
            }
            impl MaybeError for () {
                type Error = ();
                fn into_error(self) -> Option<()> {
                    None
                }
            }
            impl<E: Debug> MaybeError for Result<(), E> {
                type Error = E;
                fn into_error(self) -> Option<E> {
                    self.err()
                }
            }

            async fn #main_ident() {
                #input
                if let Some(err) = MaybeError::into_error(#main_ident().await) {
                    panic!("Error: {:?}", err);
                }
            }

            Box::pin(#main_ident())
        }
    })
}
