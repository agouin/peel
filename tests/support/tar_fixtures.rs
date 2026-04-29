//! In-memory builders for USTAR/PAX test fixtures.
//!
//! `peel::sink::tar` ships an internal copy of these helpers behind
//! `#[cfg(test)]` for its unit tests. Integration tests do not see
//! `#[cfg(test)]`-only items in the library, so we duplicate the
//! small fixture builder here. The duplication is intentional —
//! exposing the helpers from the library would require a public-API
//! surface that production callers do not need.
//!
//! The helpers build *exactly* what a real `gnu tar` archive looks
//! like for the formats we accept (USTAR + PAX 'x'); they are not a
//! full tar implementation.

#![allow(dead_code)] // Different integration tests use different subsets.

/// Tar block size.
pub const BLOCK: usize = 512;

/// Build a USTAR header with the given fields. `name` is split
/// across the prefix/name fields automatically when its length
/// exceeds 100 bytes.
pub fn build_header(name: &str, size: u64, type_flag: u8) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    let bytes = name.as_bytes();
    let (prefix, leaf): (&[u8], &[u8]) = if bytes.len() <= 100 {
        (&[], bytes)
    } else {
        let split = bytes[..155.min(bytes.len())]
            .iter()
            .rposition(|&b| b == b'/')
            .unwrap_or(0);
        (&bytes[..split], &bytes[split + 1..])
    };
    h[..leaf.len()].copy_from_slice(leaf);
    h[345..345 + prefix.len()].copy_from_slice(prefix);
    let mode = if type_flag == b'5' {
        b"0000755"
    } else {
        b"0000644"
    };
    h[100..107].copy_from_slice(mode);
    h[108..115].copy_from_slice(b"0000000");
    h[116..123].copy_from_slice(b"0000000");
    let size_str = format!("{size:011o}");
    h[124..124 + size_str.len()].copy_from_slice(size_str.as_bytes());
    h[136..147].copy_from_slice(b"00000000000");
    h[156] = type_flag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    let chk = format!("{sum:06o}\0 ");
    h[148..148 + chk.len()].copy_from_slice(chk.as_bytes());
    h
}

/// Build a PAX 'x' extended header body (the bytes that go inside
/// the PAX entry's data block). Each record encodes as
/// `<len> <key>=<value>\n` where `<len>` is the total length of the
/// record including itself.
pub fn build_pax_body(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in pairs {
        let suffix_len = k.len() + v.len() + 3;
        for digits in 1..=20usize {
            let total = digits + suffix_len;
            let candidate = format!("{total}");
            if candidate.len() == digits {
                out.extend_from_slice(candidate.as_bytes());
                out.push(b' ');
                out.extend_from_slice(k.as_bytes());
                out.push(b'=');
                out.extend_from_slice(v.as_bytes());
                out.push(b'\n');
                break;
            }
        }
    }
    out
}

/// Pad a body up to the next 512-byte block with zero bytes.
pub fn pad_block(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    let rem = out.len() % BLOCK;
    if rem != 0 {
        out.resize(out.len() + (BLOCK - rem), 0);
    }
    out
}

/// The two-zero-block end-of-archive marker.
pub fn end_of_archive() -> Vec<u8> {
    vec![0u8; BLOCK * 2]
}

/// Convenience: build an archive from a list of `(name, contents)`
/// regular files, ending with the end-of-archive marker.
pub fn build_simple_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = Vec::new();
    for (name, data) in files {
        let header = build_header(name, data.len() as u64, b'0');
        archive.extend_from_slice(&header);
        archive.extend_from_slice(data);
        let pad = (BLOCK - data.len() % BLOCK) % BLOCK;
        archive.extend(std::iter::repeat_n(0u8, pad));
    }
    archive.extend_from_slice(&end_of_archive());
    archive
}
