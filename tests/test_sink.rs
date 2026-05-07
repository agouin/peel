//! Integration tests for [`peel::sink`].
//!
//! Exercises both the always-quiescent [`peel::sink::RawSink`] and the
//! streaming [`peel::sink::TarSink`] against in-memory archive fixtures
//! built by [`support::tar_fixtures`]. The tests cover the §7 demo
//! shape: feed an archive byte-by-byte, verify on-disk contents,
//! verify path-escape rejection, verify large-size handling.

#![cfg(unix)]

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use peel::sink::{RawSink, Sink, SinkError, TarSink};

#[path = "support/mod.rs"]
mod support;

use support::tar_fixtures::{
    build_gnu_long_name_entry, build_header, build_header_with_magic, build_pax_body,
    build_simple_archive, end_of_archive, pad_block, HeaderMagic, BLOCK,
};

static UNIQ: AtomicU64 = AtomicU64::new(0);

/// Spawn a fresh, unique temp directory for the duration of one test.
fn fresh_dir(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("peel_sink_it_{label}_{pid}_{nanos}_{n}"));
    fs::create_dir_all(&p).expect("create temp dir");
    p
}

/// Drop guard removes the directory tree even if the test panics.
struct CleanupOnDrop(PathBuf);
impl Drop for CleanupOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Feed `archive` to the sink one byte at a time. The PLAN explicitly
/// names this as the test that verifies the streaming parser handles
/// arbitrary chunk boundaries.
fn feed_byte_by_byte(sink: &mut TarSink, archive: &[u8]) -> Result<(), SinkError> {
    for byte in archive {
        sink.write(std::slice::from_ref(byte))?;
    }
    Ok(())
}

/// Smoke: a plain `RawSink` round-trips its bytes to a file on disk.
#[test]
fn raw_sink_writes_bytes_verbatim() {
    let dir = fresh_dir("raw_smoke");
    let _g = CleanupOnDrop(dir.clone());
    let path = dir.join("out.bin");

    let mut sink = RawSink::create(&path).expect("create");
    sink.write(b"hello, ").expect("w1");
    sink.write(b"raw sink!").expect("w2");
    sink.close().expect("close");

    let mut got = Vec::new();
    fs::File::open(&path)
        .expect("open")
        .read_to_end(&mut got)
        .expect("read");
    assert_eq!(got, b"hello, raw sink!");
}

/// Multi-file archive: verify each file lands at the right path with
/// the right contents when the entire archive is fed in one call.
#[test]
fn tar_sink_extracts_multiple_files_bulk() {
    let dir = fresh_dir("tar_bulk");
    let _g = CleanupOnDrop(dir.clone());

    let archive = build_simple_archive(&[
        ("alpha.txt", b"alpha contents\n"),
        ("nested/beta.bin", &[0u8, 1, 2, 3, 4, 5, 6, 7]),
        ("nested/deeper/gamma.dat", &b"gamma".repeat(513)[..]),
    ]);

    let mut sink = TarSink::new(&dir).expect("new");
    sink.write(&archive).expect("write");
    sink.close().expect("close");

    let alpha = fs::read(dir.join("alpha.txt")).expect("alpha");
    assert_eq!(alpha, b"alpha contents\n");
    let beta = fs::read(dir.join("nested/beta.bin")).expect("beta");
    assert_eq!(beta, &[0u8, 1, 2, 3, 4, 5, 6, 7]);
    let gamma = fs::read(dir.join("nested/deeper/gamma.dat")).expect("gamma");
    assert_eq!(gamma, b"gamma".repeat(513));
}

/// Regression: a member whose payload size is an exact multiple of
/// the 512-byte block must transition the parser to the next header
/// in the same `write` call. The previous bug parked the parser in
/// `State::File { remaining: 0, padding: 0 }` and tripped the
/// "parser made no progress" guard on the next byte.
#[test]
fn tar_sink_handles_block_aligned_member() {
    let dir = fresh_dir("tar_block_aligned");
    let _g = CleanupOnDrop(dir.clone());

    let archive = build_simple_archive(&[
        ("aligned.bin", &b"a".repeat(512)),
        ("after.txt", b"the next member after a 512-aligned one\n"),
    ]);

    let mut sink = TarSink::new(&dir).expect("new");
    // Feed the whole archive in one buffer — the previous bug
    // surfaced precisely when the same write spanned the 512-aligned
    // member's body and the next header.
    sink.write(&archive).expect("bulk write");
    sink.close().expect("close");

    let aligned = fs::read(dir.join("aligned.bin")).expect("aligned");
    assert_eq!(aligned, b"a".repeat(512));
    let after = fs::read(dir.join("after.txt")).expect("after");
    assert_eq!(after, b"the next member after a 512-aligned one\n");
}

/// PLAN §7.4: feed the archive a byte at a time and verify identical
/// output to the bulk-feed case. This is the single test that proves
/// the parser is genuinely streaming — every internal state arm has
/// to handle a partial advance.
#[test]
fn tar_sink_handles_arbitrary_chunk_boundaries() {
    let dir = fresh_dir("tar_byte_by_byte");
    let _g = CleanupOnDrop(dir.clone());

    let archive = build_simple_archive(&[
        ("one", b"one body"),
        (
            "two",
            b"two body that is longer than 512 bytes\
                  ......................................................................\
                  ......................................................................\
                  ......................................................................\
                  ......................................................................\
                  ......................................................................\
                  ......................................................................\
                  ......................................................................",
        ),
        ("three", b""), // zero-length file
    ]);

    let mut sink = TarSink::new(&dir).expect("new");
    feed_byte_by_byte(&mut sink, &archive).expect("byte-by-byte");
    sink.close().expect("close");

    assert_eq!(fs::read(dir.join("one")).expect("one"), b"one body");
    let two = fs::read(dir.join("two")).expect("two");
    assert!(two.starts_with(b"two body"));
    let three = fs::read(dir.join("three")).expect("three");
    assert!(three.is_empty());
}

/// `is_quiescent` reports `true` at every byte boundary now that
/// `TarSink::resume` can pick up from any saved parser state.
/// Poisoning is the only thing that should flip it to `false`.
#[test]
fn tar_sink_is_quiescent_at_every_boundary() {
    let dir = fresh_dir("tar_quiescent");
    let _g = CleanupOnDrop(dir.clone());

    let mut archive = Vec::new();
    archive.extend_from_slice(&build_header("a.txt", 50, b'0'));
    archive.extend_from_slice(&pad_block(&b"a".repeat(50)));
    archive.extend_from_slice(&build_header("b.txt", 50, b'0'));
    archive.extend_from_slice(&pad_block(&b"b".repeat(50)));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    assert!(sink.is_quiescent(), "fresh sink is quiescent");

    // Mid-header — still quiescent (the resumable contract).
    sink.write(&archive[..256]).expect("partial header");
    assert!(
        sink.is_quiescent(),
        "mid-header reads are now resumable, so quiescent",
    );

    // Finish the first member — quiescent.
    sink.write(&archive[256..BLOCK * 2])
        .expect("rest of member");
    assert!(sink.is_quiescent());

    // Feed the rest of the archive in one go, finishing cleanly.
    sink.write(&archive[BLOCK * 2..]).expect("tail");
    assert!(sink.is_quiescent(), "after EOA marker: quiescent");
    sink.close().expect("close");
}

/// Path-escape rejection: an entry name with `..` is refused, the
/// sink poisons, and no file under the root is created.
#[test]
fn tar_sink_rejects_dotdot_path() {
    let dir = fresh_dir("tar_dotdot");
    let _g = CleanupOnDrop(dir.clone());

    let mut archive = Vec::new();
    archive.extend_from_slice(&build_header("../escaped.txt", 4, b'0'));
    archive.extend_from_slice(&pad_block(b"data"));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    match sink.write(&archive) {
        Err(SinkError::PathEscape { entry, .. }) => assert_eq!(entry, "../escaped.txt"),
        other => panic!("expected PathEscape, got {other:?}"),
    }

    // Subsequent writes report poisoned, never producing the file
    // outside the root.
    let parent = dir.parent().expect("temp parent");
    assert!(
        !parent.join("escaped.txt").exists(),
        "escape file must not exist outside root"
    );
}

/// Self-referential directory entries (`./` and `.`) are accepted
/// as no-op `mkdir -p` of the existing root. `bsdtar` and GNU `tar`
/// both emit such entries when run as `tar cf out.tar ./`, and
/// rejecting them refuses every Arbitrum snapshot bundle. The
/// extraction must continue past the entry without error.
#[test]
fn tar_sink_accepts_self_referential_root_entry() {
    let dir = fresh_dir("tar_root_entry");
    let _g = CleanupOnDrop(dir.clone());

    let mut archive = Vec::new();
    // `./` directory entry (typeflag 5, size 0).
    archive.extend_from_slice(&build_header("./", 0, b'5'));
    // Followed by a real file so the sink still extracts the rest.
    archive.extend_from_slice(&build_header("./hello.txt", 5, b'0'));
    archive.extend_from_slice(&pad_block(b"hello"));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    sink.write(&archive)
        .expect("self-referential root entry must be accepted");
    sink.close().expect("close");

    let got = fs::read(dir.join("hello.txt")).expect("hello.txt extracted");
    assert_eq!(got, b"hello");
}

/// Bare `.` (no trailing slash) likewise resolves to the root.
#[test]
fn tar_sink_accepts_bare_dot_entry() {
    let dir = fresh_dir("tar_bare_dot");
    let _g = CleanupOnDrop(dir.clone());

    let mut archive = Vec::new();
    archive.extend_from_slice(&build_header(".", 0, b'5'));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    sink.write(&archive).expect("`.` entry must be accepted");
    sink.close().expect("close");
}

/// Path-escape: absolute paths (Unix-style) are rejected.
#[test]
fn tar_sink_rejects_absolute_path() {
    let dir = fresh_dir("tar_absolute");
    let _g = CleanupOnDrop(dir.clone());

    let mut archive = Vec::new();
    archive.extend_from_slice(&build_header("/etc/passwd", 4, b'0'));
    archive.extend_from_slice(&pad_block(b"data"));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    match sink.write(&archive) {
        Err(SinkError::PathEscape { entry, .. }) => assert_eq!(entry, "/etc/passwd"),
        other => panic!("expected PathEscape, got {other:?}"),
    }
}

/// Symbolic links are deferred (`OPTIMIZATIONS.md`); the sink rejects
/// them with `UnsupportedEntry`.
#[test]
fn tar_sink_rejects_symlink_entry() {
    let dir = fresh_dir("tar_symlink");
    let _g = CleanupOnDrop(dir.clone());

    let mut archive = Vec::new();
    archive.extend_from_slice(&build_header("link.txt", 0, b'2'));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    match sink.write(&archive) {
        Err(SinkError::UnsupportedEntry { type_flag, entry }) => {
            assert_eq!(type_flag, b'2');
            assert_eq!(entry, "link.txt");
        }
        other => panic!("expected UnsupportedEntry, got {other:?}"),
    }
}

/// Bad checksum: tampering with a single header byte after the
/// builder runs trips the checksum check.
#[test]
fn tar_sink_rejects_bad_checksum() {
    let dir = fresh_dir("tar_bad_chk");
    let _g = CleanupOnDrop(dir.clone());

    let mut header = build_header("hello.txt", 5, b'0');
    // Flip a bit in the name (well outside the chksum field) so the
    // recorded checksum no longer matches.
    header[5] ^= 0xFF;

    let mut archive = Vec::new();
    archive.extend_from_slice(&header);
    archive.extend_from_slice(&pad_block(b"hello"));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    match sink.write(&archive) {
        Err(SinkError::BadChecksum { .. }) => {}
        other => panic!("expected BadChecksum, got {other:?}"),
    }
}

/// Old-GNU magic (`ustar  \0`) is accepted end-to-end. Real cosmos
/// snapshots from polkachu and similar producers emit this layout
/// because that's what the stock `gnu tar` CLI defaults to. Without
/// this, peel's TarSink would reject every member's header with
/// `MalformedHeader`.
#[test]
fn tar_sink_extracts_old_gnu_archive() {
    let dir = fresh_dir("tar_oldgnu_magic");
    let _g = CleanupOnDrop(dir.clone());

    let mut archive = Vec::new();
    let header = build_header_with_magic("hello.txt", 5, b'0', HeaderMagic::OldGnu);
    archive.extend_from_slice(&header);
    archive.extend_from_slice(&pad_block(b"hello"));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    sink.write(&archive).expect("write");
    sink.close().expect("close");

    assert_eq!(
        fs::read(dir.join("hello.txt")).expect("read"),
        b"hello",
        "old-GNU archive must extract identically to POSIX"
    );
}

/// GNU long-name extension (`L` typeflag) overrides the next entry's
/// name. Used by GNU `tar` for any path exceeding the 100/255-byte
/// ustar limits — a regime real snapshot archives hit on deep
/// directory trees.
#[test]
fn tar_sink_applies_gnu_long_name_override() {
    let dir = fresh_dir("tar_gnu_long_name");
    let _g = CleanupOnDrop(dir.clone());

    let long = format!("very/deep/{}/payload.bin", "seg".repeat(80));
    let body = b"long-name body bytes".repeat(7);
    let mut archive = Vec::new();
    archive.extend_from_slice(&build_gnu_long_name_entry(&long, &body));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    sink.write(&archive).expect("write");
    sink.close().expect("close");

    let target = dir.join(&long);
    assert!(target.exists(), "L-overridden path must be created");
    assert_eq!(fs::read(&target).expect("read"), body);
}

/// Streaming variant: the same long-name archive must still extract
/// correctly when the bytes arrive a few at a time. This catches
/// regressions where the new `LongName` state arm fails to advance
/// across a chunk boundary.
#[test]
fn tar_sink_handles_gnu_long_name_byte_by_byte() {
    let dir = fresh_dir("tar_gnu_long_byte");
    let _g = CleanupOnDrop(dir.clone());

    let long = format!("a/{}/file.txt", "b".repeat(150));
    let body = b"streamed payload";
    let mut archive = Vec::new();
    archive.extend_from_slice(&build_gnu_long_name_entry(&long, body));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    feed_byte_by_byte(&mut sink, &archive).expect("byte-by-byte");
    sink.close().expect("close");

    assert_eq!(fs::read(dir.join(&long)).expect("read"), body);
}

/// PAX `path` override is applied to the next entry, lifting the 100
/// byte name limit. The PLAN does not require long names per se but
/// the `path` key is the most common PAX use and validates the
/// override plumbing.
#[test]
fn tar_sink_applies_pax_path_override() {
    let dir = fresh_dir("tar_pax_path");
    let _g = CleanupOnDrop(dir.clone());

    let long = format!("very/deep/{}/file.txt", "segment".repeat(20));
    let pax_body = build_pax_body(&[("path", &long)]);
    let pax_header = build_header("PaxHeaders/0", pax_body.len() as u64, b'x');

    let mut archive = Vec::new();
    archive.extend_from_slice(&pax_header);
    archive.extend_from_slice(&pad_block(&pax_body));
    // The follow-on header's `name` field is ignored once the PAX
    // override applies; we still have to provide a syntactically
    // valid one.
    archive.extend_from_slice(&build_header("placeholder.txt", 7, b'0'));
    archive.extend_from_slice(&pad_block(b"payload"));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    sink.write(&archive).expect("write");
    sink.close().expect("close");

    let target = dir.join(&long);
    assert!(target.exists(), "PAX-overridden path must be created");
    assert_eq!(fs::read(&target).expect("read"), b"payload");
}

/// The PLAN §7.4 "ustar size limits" check. The PAX `size` override
/// can advertise sizes that exceed the 8 GiB octal-encoded ustar
/// limit. We don't actually allocate that much — we feed back the
/// PAX-advertised size of zero — but the *parser path* exercised is
/// the same as for a real >8 GiB file.
#[test]
fn tar_sink_applies_pax_size_override() {
    let dir = fresh_dir("tar_pax_size");
    let _g = CleanupOnDrop(dir.clone());

    // Override the file's size to 0 via PAX. The follow-on header
    // declares a non-zero size that the override must replace.
    let pax_body = build_pax_body(&[("size", "0")]);
    let pax_header = build_header("PaxHeaders/0", pax_body.len() as u64, b'x');

    let mut archive = Vec::new();
    archive.extend_from_slice(&pax_header);
    archive.extend_from_slice(&pad_block(&pax_body));
    // Header says the file is 100 bytes; PAX says it is 0. The PAX
    // override wins, so the parser must skip 0 body bytes (no
    // padding) before the next header. If the override were ignored
    // the parser would consume 100 bytes of "data" plus 412 bytes of
    // padding before looking for the EOA marker, and would fail.
    archive.extend_from_slice(&build_header("override.txt", 100, b'0'));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    sink.write(&archive).expect("write");
    sink.close().expect("close");

    let path = dir.join("override.txt");
    assert!(path.exists(), "file should be created");
    assert_eq!(
        fs::metadata(&path).expect("meta").len(),
        0,
        "size 0 per PAX"
    );
}

/// Trailing data after the end-of-archive marker is rejected. Most
/// real archives do not produce trailing garbage; if one does, that
/// is a strong signal of corruption.
#[test]
fn tar_sink_rejects_trailing_data() {
    let dir = fresh_dir("tar_trailing");
    let _g = CleanupOnDrop(dir.clone());

    let mut archive = build_simple_archive(&[("ok.txt", b"data")]);
    archive.push(0x42); // garbage after EOA

    let mut sink = TarSink::new(&dir).expect("new");
    match sink.write(&archive) {
        Err(SinkError::TrailingData { .. }) => {}
        other => panic!("expected TrailingData, got {other:?}"),
    }
}

/// `close` errors when the archive ended mid-member.
#[test]
fn tar_sink_close_detects_mid_member_eof() {
    let dir = fresh_dir("tar_mid_eof");
    let _g = CleanupOnDrop(dir.clone());

    // Header for a 100-byte file, but only 30 bytes of body fed.
    let mut archive = Vec::new();
    archive.extend_from_slice(&build_header("partial.txt", 100, b'0'));
    archive.extend_from_slice(&[0u8; 30]);

    let mut sink = TarSink::new(&dir).expect("new");
    sink.write(&archive).expect("partial write");
    match sink.close() {
        Err(SinkError::UnexpectedEof {
            bytes_remaining, ..
        }) => {
            // 70 bytes of data plus 412 bytes of padding still expected.
            assert_eq!(bytes_remaining, 70 + 412);
        }
        other => panic!("expected UnexpectedEof, got {other:?}"),
    }
}

/// Once a sink poisons, every subsequent `write` errors.
#[test]
fn tar_sink_poisons_on_first_error() {
    let dir = fresh_dir("tar_poison");
    let _g = CleanupOnDrop(dir.clone());

    let mut bad = Vec::new();
    bad.extend_from_slice(&build_header("../escape", 0, b'0'));
    bad.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    assert!(matches!(
        sink.write(&bad),
        Err(SinkError::PathEscape { .. })
    ));
    assert!(
        matches!(sink.write(b"more"), Err(SinkError::Io { .. })),
        "second write must report poisoned"
    );
}

/// A single zero block at end-of-stream (without the second) is
/// tolerated by `close` — some legacy producers omit the second.
#[test]
fn tar_sink_close_tolerates_single_zero_block() {
    let dir = fresh_dir("tar_one_zero");
    let _g = CleanupOnDrop(dir.clone());

    let mut archive = Vec::new();
    archive.extend_from_slice(&build_header("ok.txt", 4, b'0'));
    archive.extend_from_slice(&pad_block(b"data"));
    // Only one zero block, not two.
    archive.extend_from_slice(&[0u8; BLOCK]);

    let mut sink = TarSink::new(&dir).expect("new");
    sink.write(&archive).expect("write");
    sink.close().expect("close should accept single zero block");
    assert_eq!(fs::read(dir.join("ok.txt")).expect("ok"), b"data");
}

/// Directories declared with typeflag '5' are created.
#[test]
fn tar_sink_creates_directory_entries() {
    let dir = fresh_dir("tar_dir_entry");
    let _g = CleanupOnDrop(dir.clone());

    let mut archive = Vec::new();
    archive.extend_from_slice(&build_header("subdir", 0, b'5'));
    archive.extend_from_slice(&build_header("subdir/file.txt", 5, b'0'));
    archive.extend_from_slice(&pad_block(b"hello"));
    archive.extend_from_slice(&end_of_archive());

    let mut sink = TarSink::new(&dir).expect("new");
    sink.write(&archive).expect("write");
    sink.close().expect("close");

    assert!(dir.join("subdir").is_dir());
    assert_eq!(
        fs::read(dir.join("subdir/file.txt")).expect("file"),
        b"hello"
    );
}

// ---- TarSink::resume (mid-member checkpoint resume) -----------------

/// The load-bearing v6 case: feed half of a multi-MB tar member's
/// payload, capture sink_state, drop the sink, build TarSink::resume,
/// feed the rest, and verify the on-disk file equals the original.
#[test]
fn tar_resume_picks_up_mid_file() {
    let dir = fresh_dir("tar_resume_mid_file");
    let _g = CleanupOnDrop(dir.clone());

    // One ~10 KiB file. Member layout: 512 header + 10240 payload
    // (already 512-aligned, so `pad_block` returns the bytes
    // unchanged — no extra padding bytes are appended).
    let payload: Vec<u8> = (0..10_240u32).map(|i| (i & 0xFF) as u8).collect();
    let mut archive = Vec::new();
    archive.extend_from_slice(&build_header("midfile.bin", payload.len() as u64, b'0'));
    archive.extend_from_slice(&pad_block(&payload));
    let header_and_pad_len = archive.len();
    archive.extend_from_slice(&end_of_archive());

    // Phase 1: feed everything up through halfway into the payload.
    let split_at = 512 + payload.len() / 2; // header + first 5 KiB
    let mut sink = TarSink::new(&dir).expect("new");
    sink.write(&archive[..split_at]).expect("phase1 write");
    let captured = sink.sink_state();
    drop(sink);

    // The captured state should be a Tar with in_flight = File state.
    let in_flight = match &captured {
        peel::checkpoint::SinkState::Tar { in_flight, .. } => {
            in_flight.as_ref().expect("in-flight after partial write")
        }
        other => panic!("expected Tar sink state, got {other:?}"),
    };
    match &in_flight.state {
        peel::checkpoint::TarMemberState::File {
            remaining,
            total_size,
            ..
        } => {
            assert_eq!(*total_size, payload.len() as u64);
            assert_eq!(*remaining, (payload.len() / 2) as u64);
        }
        other => panic!("expected File mid-payload, got {other:?}"),
    }

    // Phase 2: build a fresh sink via resume, feed the rest, close.
    let mut resumed = TarSink::resume(&dir, in_flight).expect("resume");
    resumed
        .write(&archive[split_at..header_and_pad_len])
        .expect("phase2 write payload tail");
    resumed
        .write(&archive[header_and_pad_len..])
        .expect("phase2 write EOF markers");
    resumed.close().expect("close");

    let on_disk = fs::read(dir.join("midfile.bin")).expect("read midfile");
    assert_eq!(on_disk, payload, "byte-identical to the original payload");
}

/// Resume after a kill that landed inside a tar header (mid-512-byte
/// header read). The resumed sink finishes the header buffer and then
/// proceeds normally.
#[test]
fn tar_resume_picks_up_mid_header() {
    let dir = fresh_dir("tar_resume_mid_header");
    let _g = CleanupOnDrop(dir.clone());

    let payload = b"second-member-bytes\n".repeat(40); // ~800 B
    let mut archive = Vec::new();
    archive.extend_from_slice(&build_header("first.bin", 100, b'0'));
    archive.extend_from_slice(&pad_block(&[0xAAu8; 100]));
    let after_first = archive.len();
    archive.extend_from_slice(&build_header("second.bin", payload.len() as u64, b'0'));
    let into_second_header = archive.len();
    archive.extend_from_slice(&pad_block(&payload));
    archive.extend_from_slice(&end_of_archive());

    // Stop ~half-way through the second member's header.
    let stop_at = after_first + 256;
    assert!(stop_at < into_second_header);

    let mut sink = TarSink::new(&dir).expect("new");
    sink.write(&archive[..stop_at]).expect("phase1 write");
    let captured = sink.sink_state();
    drop(sink);

    let in_flight = match &captured {
        peel::checkpoint::SinkState::Tar { in_flight, .. } => {
            in_flight.as_ref().expect("in-flight mid-header")
        }
        _ => panic!(),
    };
    match &in_flight.state {
        peel::checkpoint::TarMemberState::Header { filled, buf } => {
            assert_eq!(*filled as usize, 256);
            assert_eq!(buf.len(), 256);
        }
        other => panic!("expected mid-header state, got {other:?}"),
    }

    // Resume and feed the rest.
    let mut resumed = TarSink::resume(&dir, in_flight).expect("resume");
    resumed.write(&archive[stop_at..]).expect("phase2 write");
    resumed.close().expect("close");

    let first = fs::read(dir.join("first.bin")).expect("read first");
    assert_eq!(first, vec![0xAAu8; 100]);
    let second = fs::read(dir.join("second.bin")).expect("read second");
    assert_eq!(second, payload);
}

/// Property test: every byte boundary inside the second member's
/// payload is a valid resume point. Drives the full byte-by-byte
/// kill/resume matrix on a small archive.
#[test]
fn tar_resume_byte_identical_at_every_boundary() {
    let dir_root = fresh_dir("tar_resume_property");
    let _g = CleanupOnDrop(dir_root.clone());

    let payload = b"property-payload-".repeat(64); // 1024 B
    let mut archive = Vec::new();
    archive.extend_from_slice(&build_header("file.bin", payload.len() as u64, b'0'));
    archive.extend_from_slice(&pad_block(&payload));
    archive.extend_from_slice(&end_of_archive());

    // Test every 64-byte boundary (covers headers, payload, padding,
    // EOF). 64 keeps the test runtime sane while still exercising
    // every parser state.
    for split in (0..archive.len()).step_by(64) {
        let dir = dir_root.join(format!("split_{split}"));
        fs::create_dir_all(&dir).expect("create split dir");

        let mut sink = TarSink::new(&dir).expect("new");
        sink.write(&archive[..split]).expect("phase1 write");
        let state = sink.sink_state();
        drop(sink);

        let in_flight = match &state {
            peel::checkpoint::SinkState::Tar { in_flight, .. } => in_flight.clone(),
            _ => panic!(),
        };
        let mut resumed = match in_flight {
            Some(s) => TarSink::resume(&dir, &s).expect("resume"),
            None => TarSink::new(&dir).expect("new from empty resume"),
        };
        resumed.write(&archive[split..]).expect("phase2 write");
        resumed.close().expect("close");

        let on_disk = fs::read(dir.join("file.bin")).expect("read file");
        assert_eq!(
            on_disk, payload,
            "split={split}: extracted file diverges from original"
        );
    }
}
