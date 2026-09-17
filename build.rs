fn main() {
    // `MINITCP_RELEASE` is set by the release workflow and only there, so its
    // presence is what distinguishes a published binary from a local build.
    let released = std::env::var("MINITCP_RELEASE");
    let version = released
        .clone()
        .or_else(|_| std::env::var("CARGO_PKG_VERSION"))
        .unwrap_or_else(|_| "0.0.0".into());
    // Cargo.toml's version is not bumped by the release process, so it cannot
    // be trusted to name a published image — only an explicit release can.
    println!(
        "cargo:rustc-env=MINITCP_FROM_RELEASE={}",
        u8::from(released.is_ok())
    );
    println!("cargo:rerun-if-env-changed=MINITCP_RELEASE");
    println!("cargo:rustc-env=MINITCP_RELEASE={version}");
}
