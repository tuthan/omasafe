#[path = "build_support.rs"]
mod build_support;

fn main() {
    let src = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("src");
    let (fingerprint, files) = build_support::source_fingerprint(&src).expect("core source hash");
    for directory in build_support::source_directories(&src).expect("core source directories") {
        println!("cargo:rerun-if-changed={}", directory.display());
    }
    for file in files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    println!("cargo:rustc-env=CORE_LOGIC_FINGERPRINT={fingerprint}");
}
