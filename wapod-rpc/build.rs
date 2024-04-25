fn main() {
    let out_dir = "./src/prpc/generated";

    let mut builder = prpc_build::configure()
        .out_dir(out_dir)
        .mod_prefix("crate::prpc::")
        .disable_package_emission();
    builder = builder.type_attribute(".wapod", "#[::prpc::serde_helpers::prpc_serde_bytes]");
    builder = builder.type_attribute(
        ".wapod",
        "#[derive(::serde::Serialize, ::serde::Deserialize)]",
    );
    for t in &[".wapod.Manifest", ".wapod.StringPair"] {
        builder = builder.type_attribute(t, "#[derive(::scale::Encode, ::scale::Decode)]");
    }
    builder.compile(&["wapod_rpc.proto"], &["./proto"]).unwrap();
}
