fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let header = std::path::Path::new(&crate_dir)
        .join("../../packages/crypto-native/cpp/generated/kokuin_crypto.h");
    std::fs::create_dir_all(header.parent().unwrap()).unwrap();
    let config =
        cbindgen::Config::from_file(std::path::Path::new(&crate_dir).join("cbindgen.toml"))
            .expect("read C ABI header config");
    cbindgen::Builder::new()
        .with_src(std::path::Path::new(&crate_dir).join("src/lib.rs"))
        .with_config(config)
        .generate()
        .expect("generate C ABI header")
        .write_to_file(header);
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
