//! Fuzz target: ZIP archive parsing.
//!
//! ZIP doesn't run through the streaming-decoder loop covered by
//! `frame_boundary` — its central-directory-at-the-end layout requires a
//! different pipeline (`internal/PLAN_v2.md` §5). This target fuzzes the
//! three parser entry points that consume archive bytes:
//!
//! - `find_eocd` (locate end-of-central-directory in the archive tail),
//! - `parse_central_directory` (decode CD entries),
//! - `LocalFileHeader::parse` (decode an LFH at a known archive offset).
//!
//! The first input byte selects which parser receives the rest, so
//! libfuzzer can specialize per parser while sharing a corpus directory.
//!
//! Required per `internal/ENGINEERING_STANDARDS.md` §5.2 ("frame boundary
//! detection") for the ZIP format.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peel::zip::format::{find_eocd, parse_central_directory, LocalFileHeader};

fuzz_target!(|data: &[u8]| {
    let Some((selector, body)) = data.split_first() else {
        return;
    };

    match selector % 3 {
        0 => {
            // The archive_total_size argument bounds where the EOCD
            // can plausibly start. Picking `body.len()` matches the
            // realistic call site (search the tail of an archive
            // whose total size is the byte count seen so far).
            let _ = find_eocd(body, body.len() as u64);
        }
        1 => {
            // expected_count is fuzzer-driven via the next byte so
            // the parser's count-mismatch path is reachable. Cap at
            // 256 to avoid the parser spinning on a contrived
            // u32::MAX claim before consulting the bytes.
            let (count_byte, cd_bytes) = body.split_first().unwrap_or((&0, &[]));
            let _ = parse_central_directory(cd_bytes, 0, u32::from(*count_byte));
        }
        _ => {
            let _ = LocalFileHeader::parse(body, 0);
        }
    }
});
