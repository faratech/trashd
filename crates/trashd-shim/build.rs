use std::env;

// Stamp the same build-time version the CLI uses (release.yml sets
// TRASHD_VERSION for date-based tags), so --version agrees across the
// release's binaries instead of shim/daemon reporting CARGO_PKG_VERSION
// while the CLI reports the release tag (#163).
fn build_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        env::var("TRASHD_VERSION").unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
    })
}

fn main() {
    println!("cargo:rerun-if-env-changed=TRASHD_VERSION");
    println!("cargo:rustc-env=TRASHD_VERSION={}", build_version());
}
