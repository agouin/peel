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

/// Magic flavors `build_header` can emit.
#[derive(Clone, Copy)]
pub enum HeaderMagic {
    /// POSIX/USTAR (POSIX.1-1988): `ustar\0` + version `00`.
    Posix,
    /// Old-GNU (GNU tar default): `ustar  \0` (5 chars + 2 spaces +
    /// NUL). Required to extract polkachu-style cosmos snapshots.
    OldGnu,
}

/// Build a USTAR header with the given fields. `name` is split
/// across the prefix/name fields automatically when its length
/// exceeds 100 bytes.
pub fn build_header(name: &str, size: u64, type_flag: u8) -> [u8; BLOCK] {
    build_header_with_magic(name, size, type_flag, HeaderMagic::Posix)
}

/// Like [`build_header`] but lets the caller pick which magic +
/// version pair the header carries — used to fuzz the sink against
/// both POSIX and old-GNU archives.
pub fn build_header_with_magic(
    name: &str,
    size: u64,
    type_flag: u8,
    magic: HeaderMagic,
) -> [u8; BLOCK] {
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
    match magic {
        HeaderMagic::Posix => {
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
        }
        HeaderMagic::OldGnu => {
            h[257..265].copy_from_slice(b"ustar  \x00");
        }
    }
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    let chk = format!("{sum:06o}\0 ");
    h[148..148 + chk.len()].copy_from_slice(chk.as_bytes());
    h
}

/// Build a symlink (`2`) or hard-link (`1`) header whose `linkname`
/// field carries `target` (truncated to the 100-byte field). Link
/// entries declare size 0. The checksum is recomputed after the
/// linkname bytes are written so the header validates.
pub fn build_link_header(name: &str, target: &str, type_flag: u8) -> [u8; BLOCK] {
    let mut h = build_header(name, 0, type_flag);
    let tb = target.as_bytes();
    let n = tb.len().min(100);
    h[157..157 + n].copy_from_slice(&tb[..n]);
    // The linkname bytes participate in the checksum; redo the
    // spaces-then-sum dance `build_header` performs.
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    let chk = format!("{sum:06o}\0 ");
    h[148..148 + chk.len()].copy_from_slice(chk.as_bytes());
    h
}

/// Build a GNU `K` (long-link) extension preamble followed by a link
/// header: emits a `K` header whose body holds the NUL-terminated
/// long link target, then `link_header` (whose own `linkname` field
/// holds a truncated stub the sink ignores in favor of the `K`
/// payload). Mirrors [`build_gnu_long_name_entry`] for link targets.
pub fn build_gnu_long_link_entry(long_target: &str, link_header: &[u8; BLOCK]) -> Vec<u8> {
    let mut payload = long_target.as_bytes().to_vec();
    payload.push(0);
    let k_header = build_header_with_magic(
        "././@LongLink",
        payload.len() as u64,
        b'K',
        HeaderMagic::OldGnu,
    );
    let mut out = Vec::new();
    out.extend_from_slice(&k_header);
    out.extend_from_slice(&pad_block(&payload));
    out.extend_from_slice(link_header);
    out
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

/// Build an old-GNU `L` (long-name) extension preamble for a regular
/// file: emits an `L` header whose body holds the NUL-terminated
/// long path, followed by the regular header (with a truncated name
/// per GNU conventions) and the file body.
///
/// The two regular header fields (name + prefix) are filled with the
/// first up-to-100 bytes of `name`; real GNU `tar` writes the same
/// truncated stub even though the L extension is what actually
/// names the entry. The sink must apply the L payload as a
/// `pending_path` override.
pub fn build_gnu_long_name_entry(long_path: &str, data: &[u8]) -> Vec<u8> {
    // GNU pads the long-name body with a single NUL terminator and
    // zero-fills to a 512-byte boundary.
    let mut payload = long_path.as_bytes().to_vec();
    payload.push(0);
    // The L header records the *unpadded* payload length. Use the
    // sentinel name "./@LongLink" that real GNU tar emits — the sink
    // must ignore it in favor of the body.
    let l_header = build_header_with_magic(
        "./@LongLink",
        payload.len() as u64,
        b'L',
        HeaderMagic::OldGnu,
    );
    // GNU writes a *truncated* stub into the regular header's
    // name+prefix fields — anything longer than 100 bytes won't fit
    // in the leaf field at all without clobbering mode/size/cksum,
    // so we stuff a short placeholder. The sink ignores this stub
    // because the L extension above sets `pending_path`.
    let bytes = long_path.as_bytes();
    let stub_len = bytes.len().min(99);
    let stub = std::str::from_utf8(&bytes[..stub_len]).expect("ascii-clean test paths only");
    let regular = build_header_with_magic(stub, data.len() as u64, b'0', HeaderMagic::OldGnu);
    let mut out = Vec::new();
    out.extend_from_slice(&l_header);
    out.extend_from_slice(&pad_block(&payload));
    out.extend_from_slice(&regular);
    out.extend_from_slice(data);
    let pad = (BLOCK - data.len() % BLOCK) % BLOCK;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}
