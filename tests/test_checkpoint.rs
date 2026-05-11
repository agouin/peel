//! Integration tests for [`peel::checkpoint`].
//!
//! These exercise the §9 demo shape: round-trip a checkpoint through a
//! real on-disk file, verify the atomic rename leaves no partial state
//! behind, confirm partial-write recovery falls back to the previous
//! checkpoint, and check the forward-compatibility guard fires on a
//! checkpoint declared at a higher version than this build supports.
//!
//! Lower-level tests of the binary format (bad magic, bad presence
//! byte, invalid sink tag, etc.) live next to the implementation in
//! `src/checkpoint.rs`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use peel::checkpoint::{
    tmp_path_for, Checkpoint, CheckpointError, RunMode, SinkState, FORMAT_VERSION,
};
use peel::types::ByteOffset;

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_temp(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("peel_checkpoint_it_{label}_{pid}_{nanos}_{n}.ckpt"))
}

struct CleanupOnDrop(PathBuf);
impl Drop for CleanupOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(tmp_path_for(&self.0));
    }
}

fn realistic_tar_checkpoint() -> Checkpoint {
    let url = "https://releases.example.com/v2/dataset-2026-04.tar.zst".to_string();
    let etag = Some("\"4abf2c9-e8b1\"".to_string());
    let last_modified = Some("Tue, 28 Apr 2026 10:00:00 GMT".to_string());
    let total_size = 12 * 1024 * 1024 * 1024u64;
    Checkpoint {
        url: url.clone(),
        etag: etag.clone(),
        last_modified: last_modified.clone(),
        parts: vec![peel::checkpoint::PartRecord {
            url,
            size: total_size,
            etag,
            last_modified,
            expected_sha256: None,
        }],
        total_size,
        chunk_size: 4 * 1024 * 1024,
        decoder_position: ByteOffset::new(2 * 1024 * 1024 * 1024 + 42),
        bitmap_completed: (0u8..=200).cycle().take(8192).collect(),
        created_at: UNIX_EPOCH + Duration::new(1_745_846_400, 0),
        sink_state: SinkState::Tar {
            members_completed: vec![
                "linux-6.10/Documentation/index.html".into(),
                "linux-6.10/MAINTAINERS".into(),
                "linux-6.10/Makefile".into(),
            ],
            in_flight: None,
        },
        hash_state: None,
        chunk_crc32c: None,
        decoder_state: None,
        mode: RunMode::Extract,
        source_mtime: None,
    }
}

/// Round-trip the realistic checkpoint through a real on-disk file
/// path and verify byte-for-byte equality. Validates the §9.3
/// write→fsync→rename happy path end-to-end.
#[test]
fn write_and_read_round_trip_via_disk() {
    let path = unique_temp("happy");
    let _g = CleanupOnDrop(path.clone());

    let original = realistic_tar_checkpoint();
    original.write(&path).expect("write");

    let parsed = Checkpoint::read(&path).expect("read").expect("present");
    assert_eq!(parsed, original);

    // The atomic rename should have moved the .tmp into place; no
    // .tmp must remain on disk.
    assert!(!tmp_path_for(&path).exists(), "stale .tmp file");
}

/// `Checkpoint::read` distinguishes "no checkpoint here" from "a
/// checkpoint exists but is malformed" — `Ok(None)` for the former.
#[test]
fn read_returns_none_for_first_run() {
    let path = unique_temp("first-run");
    let parsed = Checkpoint::read(&path).expect("read");
    assert!(parsed.is_none(), "first run must return None, not Err");
}

/// Plan §9.4: partial-write recovery. Simulate a process killed
/// after writing the .tmp but before the rename, with a valid prior
/// .ckpt already in place. The reader must still see the prior
/// checkpoint, untouched. The .tmp's contents are irrelevant to the
/// reader because reads only look at the .ckpt path.
#[test]
fn partial_write_falls_back_to_prior_checkpoint() {
    let path = unique_temp("partial");
    let _g = CleanupOnDrop(path.clone());

    let prior = realistic_tar_checkpoint();
    prior.write(&path).expect("first write");

    // Stage a plausible-but-incomplete second write: a half-buffered
    // checkpoint on the .tmp path with no rename yet. We are
    // deliberately writing arbitrary bytes here — the rename never
    // happened, so the reader must not look at .tmp.
    let tmp = tmp_path_for(&path);
    {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .expect("open tmp");
        f.write_all(b"partial garbage from a crashed writer")
            .unwrap();
        f.sync_all().unwrap();
    }

    let parsed = Checkpoint::read(&path).expect("read").expect("present");
    assert_eq!(parsed, prior, "reader followed the .tmp instead of .ckpt");
    // The stale .tmp lingers; the next successful write would
    // overwrite it. Verified separately in `next_write_overwrites_stale_tmp`.
    assert!(tmp.exists(), "test setup failed to leave .tmp behind");
}

/// Plan §9.4: a successful subsequent write overwrites whatever stale
/// .tmp the previous crash left behind, so the .tmp isn't a permanent
/// disk leak.
#[test]
fn next_write_overwrites_stale_tmp() {
    let path = unique_temp("overwrite-tmp");
    let _g = CleanupOnDrop(path.clone());

    let tmp = tmp_path_for(&path);
    fs::write(&tmp, vec![0u8; 64]).unwrap();

    let ckpt = realistic_tar_checkpoint();
    ckpt.write(&path).expect("write");

    // After the write the .tmp must have been renamed away, so its
    // original path no longer exists.
    assert!(!tmp.exists(), "stale .tmp survived next write");
    let parsed = Checkpoint::read(&path).expect("read").expect("present");
    assert_eq!(parsed, ckpt);
}

/// Plan §9.4: a corrupted .ckpt (single-byte flip in the body) is
/// surfaced as [`CheckpointError::BodyChecksumMismatch`] rather than
/// silently dropped. The §10 coordinator decides whether to surface
/// this to the user or restart from scratch.
#[test]
fn corrupted_checkpoint_surfaces_typed_error() {
    let path = unique_temp("corrupt");
    let _g = CleanupOnDrop(path.clone());

    let ckpt = realistic_tar_checkpoint();
    ckpt.write(&path).expect("write");

    // Flip a single bit deep in the body so the framing still parses
    // but the checksum mismatches.
    let mut bytes = fs::read(&path).expect("read raw");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x40;
    fs::write(&path, &bytes).expect("rewrite");

    match Checkpoint::read(&path).unwrap_err() {
        CheckpointError::BodyChecksumMismatch { .. } => {}
        other => panic!("expected BodyChecksumMismatch, got {other:?}"),
    }
}

/// Plan §9.4: forward-compatibility. An older binary asked to read a
/// checkpoint declared at a newer `format_version` must fail cleanly
/// with a clear error, never partially parse the unknown body
/// layout.
#[test]
fn forward_compat_rejects_newer_format_version() {
    let path = unique_temp("newer");
    let _g = CleanupOnDrop(path.clone());

    let ckpt = realistic_tar_checkpoint();
    let mut bytes = ckpt.serialize();
    let bumped = (FORMAT_VERSION + 5).to_le_bytes();
    bytes[8..12].copy_from_slice(&bumped);
    fs::write(&path, &bytes).expect("write tampered");

    match Checkpoint::read(&path).unwrap_err() {
        CheckpointError::UnsupportedVersion {
            found,
            supported_max,
        } => {
            assert_eq!(found, FORMAT_VERSION + 5);
            assert_eq!(supported_max, FORMAT_VERSION);
        }
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

/// Regression test for a fuzz-discovered crash: a checkpoint header
/// that declares `format_version == 0` previously slipped past the
/// "newer than supported" check and tripped a `debug_assert!` in
/// `decode_body`. The deserializer's contract is "never panics on
/// adversarial input"; v0 must be rejected with `UnsupportedVersion`.
#[test]
fn rejects_format_version_zero() {
    let path = unique_temp("v0");
    let _g = CleanupOnDrop(path.clone());

    let ckpt = realistic_tar_checkpoint();
    let mut bytes = ckpt.serialize();
    bytes[8..12].copy_from_slice(&0u32.to_le_bytes());
    fs::write(&path, &bytes).expect("write tampered");

    match Checkpoint::read(&path).unwrap_err() {
        CheckpointError::UnsupportedVersion {
            found,
            supported_max,
        } => {
            assert_eq!(found, 0);
            assert_eq!(supported_max, FORMAT_VERSION);
        }
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

/// Plan §9: the format is *not* JSON — peeking at the first eight
/// bytes of a written file should observe the magic the reader
/// validates against. Keeps anyone tempted to add a JSON parser later
/// honest.
#[test]
fn on_disk_layout_starts_with_ascii_magic() {
    let path = unique_temp("magic");
    let _g = CleanupOnDrop(path.clone());

    realistic_tar_checkpoint().write(&path).expect("write");

    let bytes = fs::read(&path).expect("read raw");
    assert!(bytes.len() >= 8);
    assert_eq!(&bytes[0..8], b"peelckpt");
    assert_ne!(bytes[0], b'{', "checkpoint must not be JSON");
}

/// Two consecutive writes leave only the .ckpt; the reader sees the
/// most recent one. Validates that the .ckpt path can be safely
/// rewritten over time without any cleanup ceremony.
#[test]
fn writes_replace_each_other_atomically() {
    let path = unique_temp("replace");
    let _g = CleanupOnDrop(path.clone());

    let mut ckpt = realistic_tar_checkpoint();
    ckpt.write(&path).expect("first write");

    ckpt.decoder_position = ByteOffset::new(ckpt.decoder_position.get() + 4 * 1024 * 1024);
    if let SinkState::Tar {
        ref mut members_completed,
        ..
    } = ckpt.sink_state
    {
        members_completed.push("linux-6.10/scripts/checkpatch.pl".into());
    }
    ckpt.write(&path).expect("second write");

    let parsed = Checkpoint::read(&path).expect("read").expect("present");
    assert_eq!(parsed, ckpt);
    assert!(!tmp_path_for(&path).exists());
}

/// The raw-sink variant round-trips just like the tar variant. We
/// assert this end-to-end in tests/ rather than only in the unit
/// tests because §10 will use *both* variants depending on the
/// archive shape.
#[test]
fn round_trip_raw_sink_state() {
    let path = unique_temp("raw");
    let _g = CleanupOnDrop(path.clone());

    let url = "https://example.com/blob.zst".to_string();
    let total_size = 1_500_000u64;
    let ckpt = Checkpoint {
        url: url.clone(),
        etag: None,
        last_modified: None,
        parts: vec![peel::checkpoint::PartRecord {
            url,
            size: total_size,
            etag: None,
            last_modified: None,
            expected_sha256: None,
        }],
        total_size,
        chunk_size: 65_536,
        decoder_position: ByteOffset::new(196_608),
        bitmap_completed: vec![0xFFu8; (1_500_000u64.div_ceil(65_536) as usize).div_ceil(8)],
        created_at: UNIX_EPOCH + Duration::new(2_000_000_000, 0),
        sink_state: SinkState::Raw {
            bytes_written: 524_288,
        },
        hash_state: None,
        chunk_crc32c: None,
        decoder_state: None,
        mode: RunMode::Extract,
        source_mtime: None,
    };
    ckpt.write(&path).expect("write");

    let parsed = Checkpoint::read(&path).expect("read").expect("present");
    assert_eq!(parsed, ckpt);
}
