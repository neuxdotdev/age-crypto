use std::env;
use std::path::PathBuf;
fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_file = PathBuf::from(&crate_dir).join("clib").join("age-crypto.h");
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_language(cbindgen::Language::C)
        .with_include_guard("AGE_CRYPTO_H")
        .with_include("stdint.h")
        .with_include("stdlib.h")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(output_file);
}
