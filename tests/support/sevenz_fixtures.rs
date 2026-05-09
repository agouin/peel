//! In-memory builder for COPY-coded 7z test archives.
//!
//! Mirrors the tar/zip fixture builders: integration tests synthesize
//! archives in code rather than checking binary fixtures into the
//! repo. Wire-format details follow the 7z layout that
//! `peel::decode::sevenz::header` parses (`docs/PLAN_7z_support.md`
//! §"On-the-wire layout"). Only COPY-coded, plain-Header,
//! single-folder archives are generated here — that's the minimum
//! shape the §3-§9 tests in `peel::download::sevenz_pipeline` already
//! drive end-to-end, and it's what the bench grid uses to compare
//! against `7z x` (which decodes COPY-coded archives identically to
//! any other coder, just faster).
//!
//! Mirrors `build_copy_sevenz` from
//! [`peel::download::sevenz_pipeline`]'s test module — kept in sync by
//! deliberate copy because the source-side helper is `#[cfg(test)]`
//! and not reachable from integration tests.

#![allow(dead_code)] // Different integration tests use different subsets.

use peel::decode::sevenz::header::nid;

/// Encode `value` to the 7z `Number` format used throughout the
/// header (variable-length, big-endian length prefix in the high
/// bits of the first byte).
fn encode_number(value: u64) -> Vec<u8> {
    if value < (1u64 << 7) {
        return vec![value as u8];
    }
    for size in 2u32..=8 {
        let bits = 7 * size;
        let max = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        if value <= max {
            let leading_ones = size - 1;
            let header_top = ((1u8 << leading_ones) - 1) << (8 - leading_ones);
            let high_value = value >> (8 * (size as u64 - 1));
            let header = header_top | (high_value as u8);
            let mut out = Vec::with_capacity(size as usize);
            out.push(header);
            for i in 0..(size - 1) {
                out.push((value >> (8 * i)) as u8);
            }
            return out;
        }
    }
    let mut out = Vec::with_capacity(9);
    out.push(0xFF);
    for i in 0..8 {
        out.push((value >> (8 * i)) as u8);
    }
    out
}

/// CRC-32/IEEE table-driven implementation, polynomial 0xEDB88320.
fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Build a complete 7z archive with one folder, a single COPY coder,
/// containing the named files. The packed stream is the concatenation
/// of every file's raw bytes; SubStreamsInfo records the per-file
/// boundaries.
///
/// `files` is a list of `(name, payload)` pairs. `name` is the
/// archive-relative path as recorded in the FilesInfo block (UTF-16LE
/// on the wire); `payload` is the raw uncompressed bytes for that
/// file.
pub fn build_copy_sevenz(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    build_copy_sevenz_with_trailer_padding(files, 0)
}

/// Variant of [`build_copy_sevenz`] that pads the trailer with
/// `padding_bytes` of `kArchiveProperties` body. Useful for
/// testing the "trailer larger than `max_disk_buffer`" path:
/// peel's pipeline exempts the trailer fetch from the cap, so a
/// trailer that spans many chunks must still extract under a
/// tight cap. The §3 parser accepts and skips
/// `kArchiveProperties` bodies, so the padding is invisible to
/// the rest of the extractor.
///
/// `padding_bytes` is the size of the inflated property's body;
/// the on-the-wire trailer overhead is roughly `padding_bytes +
/// a few bytes of variable-length integer headers`.
pub fn build_copy_sevenz_with_trailer_padding(
    files: &[(&str, Vec<u8>)],
    padding_bytes: usize,
) -> Vec<u8> {
    assert!(
        !files.is_empty(),
        "build_copy_sevenz_with_trailer_padding: at least one file"
    );

    // Concatenated packed bytes (all files' raw bytes).
    let pack_bytes: Vec<u8> = files.iter().flat_map(|(_, p)| p.clone()).collect();
    let pack_size = pack_bytes.len() as u64;
    let primary_unpack_size = pack_size;

    // Trailer: Header (0x01) + (optional ArchiveProperties)
    // + MainStreamsInfo + FilesInfo + End.
    let mut trailer = vec![nid::HEADER];

    // Optional ArchiveProperties block sized to the requested
    // padding. The §3 parser's `skip_archive_properties` walks
    // a sequence of `(propid, size, body)` pairs terminated by
    // `kEnd`; one big property with a `padding_bytes`-sized
    // body is the simplest shape that's still legal.
    if padding_bytes > 0 {
        trailer.push(nid::ARCHIVE_PROPERTIES);
        // Inner property: propid 0x42 (arbitrary unused), size
        // = padding_bytes, body = padding_bytes zero bytes.
        trailer.push(0x42);
        trailer.extend(encode_number(padding_bytes as u64));
        trailer.extend(std::iter::repeat_n(0u8, padding_bytes));
        trailer.push(nid::END);
    }

    // MainStreamsInfo
    trailer.push(nid::MAIN_STREAMS_INFO);
    // PackInfo
    trailer.push(nid::PACK_INFO);
    trailer.extend(encode_number(0)); // pack_pos
    trailer.extend(encode_number(1)); // num_pack_streams
    trailer.push(nid::SIZE);
    trailer.extend(encode_number(pack_size));
    trailer.push(nid::END);

    // UnPackInfo
    trailer.push(nid::UNPACK_INFO);
    trailer.push(nid::FOLDER);
    trailer.extend(encode_number(1)); // NumFolders
    trailer.push(0x00); // External=0
    trailer.extend(encode_number(1)); // NumCoders
    trailer.push(0x01); // flags: idSize=1, simple
    trailer.push(0x00); // codec id COPY
                        // No bind pairs (NumOutStreams - 1 = 0)
                        // No PackedStreamIndices (NumPackedStreams = 1)
    trailer.push(nid::CODERS_UNPACK_SIZE);
    trailer.extend(encode_number(primary_unpack_size));
    trailer.push(nid::END);

    // SubStreamsInfo: tells the parser to split the folder's single
    // unpack stream into one substream per file.
    trailer.push(nid::SUBSTREAMS_INFO);
    trailer.push(nid::NUM_UNPACK_STREAM);
    trailer.extend(encode_number(files.len() as u64));
    trailer.push(nid::SIZE);
    // For NumSubstreams - 1 of them, encode the size; the last is
    // implied = primary_unpack_size - sum of others.
    for (_, payload) in &files[..files.len() - 1] {
        trailer.extend(encode_number(payload.len() as u64));
    }
    trailer.push(nid::END);

    // StreamsInfo End
    trailer.push(nid::END);

    // FilesInfo: one entry per file. UTF-16LE NUL-terminated names,
    // packed contiguously after a single external=0 byte.
    trailer.push(nid::FILES_INFO);
    trailer.extend(encode_number(files.len() as u64));
    trailer.push(nid::NAME);
    let mut name_body = vec![0x00u8]; // external = 0
    for (name, _) in files {
        for u in name.encode_utf16() {
            name_body.extend_from_slice(&u.to_le_bytes());
        }
        name_body.extend_from_slice(&[0x00, 0x00]);
    }
    trailer.extend(encode_number(name_body.len() as u64));
    trailer.extend(name_body);
    trailer.push(nid::END);

    // Header End
    trailer.push(nid::END);

    // SignatureHeader (32 bytes) + pack data + trailer.
    let trailer_offset = pack_size; // relative to byte 32
    let trailer_len = trailer.len() as u64;
    let trailer_crc = crc32_ieee(&trailer);

    let mut start_header_body = Vec::with_capacity(20);
    start_header_body.extend(trailer_offset.to_le_bytes());
    start_header_body.extend(trailer_len.to_le_bytes());
    start_header_body.extend(trailer_crc.to_le_bytes());
    let start_header_crc = crc32_ieee(&start_header_body);

    let mut archive = Vec::with_capacity(32 + pack_bytes.len() + trailer.len());
    archive.extend_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]); // magic
    archive.push(0x00); // ArchiveVersion.major
    archive.push(0x04); // ArchiveVersion.minor
    archive.extend_from_slice(&start_header_crc.to_le_bytes());
    archive.extend(start_header_body);
    archive.extend(pack_bytes);
    archive.extend(trailer);
    archive
}
