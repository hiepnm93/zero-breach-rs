//! zero-breach-rs — local, read-only detector for AdFection / Candiru
//! indicators. Ported from zero-breach
//! (https://github.com/interplains/zero-breach, commit 1c7e9b6, Apache-2.0);
//! an unofficial port, not affiliated with or endorsed by upstream.

fn main() {
    let mut argv: Vec<String> = std::env::args().collect();
    // clap expects argv[0] to be the program name; keep it.
    if argv.is_empty() {
        argv.push("zero-breach".to_string());
    }
    std::process::exit(zero_breach_rs::cli::main(argv));
}
