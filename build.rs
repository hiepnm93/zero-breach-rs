//! Build script: capture the rustc release so the JSON report can name the
//! toolchain in the slot the Python report used for the interpreter version.

fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    if let Ok(out) = std::process::Command::new(rustc).arg("-vV").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(release) = line.strip_prefix("release: ") {
                println!("cargo:rustc-env=ZB_RUSTC_RELEASE={}", release);
            }
        }
    }
    println!("cargo:rerun-if-changed=build.rs");
}
