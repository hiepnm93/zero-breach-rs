//! zero-breach-rs — local, read-only detector for AdFection / Candiru
//! indicators. Unofficial Rust port of zero-breach
//! (https://github.com/interplains/zero-breach, Apache-2.0).

fn main() {
    let mut argv: Vec<String> = std::env::args().collect();
    // clap expects argv[0] to be the program name; keep it.
    if argv.is_empty() {
        argv.push("zero-breach".to_string());
    }
    std::process::exit(zero_breach_rs::cli::main(argv));
}
