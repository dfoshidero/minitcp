fn main() {
    let version = std::env::var("MINITCP_RELEASE")
        .or_else(|_| std::env::var("CARGO_PKG_VERSION"))
        .unwrap_or_else(|_| "0.0.0".into());
    println!("cargo:rerun-if-env-changed=MINITCP_RELEASE");
    println!("cargo:rustc-env=MINITCP_RELEASE={version}");
}
