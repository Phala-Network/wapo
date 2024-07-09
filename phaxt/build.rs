use scale::Decode;
use subxt_codegen::{CodegenBuilder, Metadata};

fn main() {
    println!("cargo:rerun-if-changed=phala_metadata.scale");

    let output_filename = "src/phala_metadata.rs";

    let metadata = include_bytes!("./phala_metadata.scale");
    let metadata = Metadata::decode(&mut &metadata[..]).unwrap();
    let mut builder = CodegenBuilder::new();
    builder.set_target_module(syn::parse_quote! { mod phala {} });
    builder.add_derives_for_type(
        syn::parse_quote!(phala_pallets::wapod_workers::pallet::TicketInfo),
        [syn::parse_quote! { Clone }],
        true,
    );
    builder.add_derives_for_type(
        syn::parse_quote!(wapod_types::ticket::Prices),
        [syn::parse_quote! { Default }],
        true,
    );

    let code = builder.generate(metadata).unwrap().to_string();
    std::fs::write(output_filename, code).unwrap();
    std::process::Command::new("rustfmt")
        .arg(output_filename)
        .status()
        .unwrap();
}
