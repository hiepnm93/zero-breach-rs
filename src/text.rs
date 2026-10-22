//! Small shared text helpers: hashing, base64 (for the HSTS fingerprint) and
//! the `{:,}` thousands separator the Python reports used. These stand in for
//! `hashlib`, `base64` and `str.format` from zero-breach (Apache-2.0).

use sha2::{Digest, Sha256};

/// Lower-case hex SHA-256 of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Standard base64 with padding, of a SHA-256 digest.
pub fn sha256_b64(data: &[u8]) -> String {
    base64_encode(&{
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().to_vec()
    })
}

const B64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with `=` padding.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64_ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Python's `"{:,}".format(n)` — thousands separated by commas.
pub fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let bytes = s.as_bytes();
    for (i, c) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*c as char);
    }
    out
}

/// Python's `"{:,}".format(n)` for signed counts.
pub fn fmt_count_i(n: i64) -> String {
    if n < 0 {
        format!("-{}", fmt_count(n.unsigned_abs()))
    } else {
        fmt_count(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // sha256 of the DNS wire form of "a.example" as base64, matching the
        // worked example in the browser module's documentation.
        assert_eq!(base64_encode(&[0x61, 0x62, 0x63]), "YWJj");
        assert_eq!(base64_encode(&[0x61, 0x62]), "YWI=");
        assert_eq!(base64_encode(&[0x61]), "YQ==");
    }

    #[test]
    fn counts() {
        assert_eq!(fmt_count(1_073_741_824), "1,073,741,824");
        assert_eq!(fmt_count(7), "7");
        assert_eq!(fmt_count(1_000), "1,000");
        assert_eq!(fmt_count_i(-12_345), "-12,345");
    }
}
