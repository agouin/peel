//! End-to-end smoke test for the §1 demo binary.
//!
//! Synthesizes a RAR5 fixture, runs `examples/rar_list.rs` against
//! it as a subprocess, and asserts that:
//!
//! - The signature path / non-solid / 3-entry archive prints the
//!   per-entry metadata and exits 0.
//! - The archive-encryption rejection surfaces the
//!   `unsupported RAR feature: encryption` line on stderr and
//!   exits 1.
//!
//! This is the §1 milestone marker per `internal/PLAN_rar.md` §1: the
//! demo runs without any §3 pipeline / §4 decoder code.

#![cfg(feature = "rar")]

#[path = "support/mod.rs"]
mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use support::rar_fixtures::{build_rar5, build_rar5_encrypted_header, RarEntrySpec};

/// Path to the built example binary. Cargo sets `CARGO_BIN_EXE_*`
/// for `[[bin]]` targets only; for examples we rely on
/// `cargo run --example` indirection so test runs pick up the
/// freshly compiled artifact regardless of the target directory's
/// layout.
fn run_example(input_path: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO"))
        .args(["run", "--quiet", "--example", "rar_list", "--"])
        .arg(input_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run rar_list example")
}

fn write_tempfile(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("peel-rar-list-{}-{}.rar", std::process::id(), name));
    let mut f = std::fs::File::create(&path).expect("create tempfile");
    f.write_all(bytes).expect("write tempfile");
    path
}

#[test]
fn rar_list_lists_three_stored_entries() {
    let archive = build_rar5(
        0,
        None,
        &[
            RarEntrySpec::stored("alpha.txt", b"hello".to_vec()),
            RarEntrySpec::stored("nested/beta.txt", b"world!".to_vec()),
            RarEntrySpec::stored("gamma.bin", vec![0x42; 64]),
        ],
    );
    let path = write_tempfile("ok", &archive);
    let out = run_example(&path);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "exit status {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert!(
        stdout.contains("solid:           false"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("entries: 3"), "stdout: {stdout}");
    assert!(stdout.contains("alpha.txt"), "stdout: {stdout}");
    assert!(stdout.contains("nested/beta.txt"), "stdout: {stdout}");
    assert!(stdout.contains("gamma.bin"), "stdout: {stdout}");
    assert!(stdout.contains("method=STORED"), "stdout: {stdout}");
}

#[test]
fn rar_list_reports_encryption_diagnostic() {
    let archive = build_rar5_encrypted_header(&[RarEntrySpec::stored("locked.txt", b"x".to_vec())]);
    let path = write_tempfile("enc", &archive);
    let out = run_example(&path);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let _ = std::fs::remove_file(&path);
    assert!(
        !out.status.success(),
        "expected non-zero exit, got {:?}\nstderr:\n{stderr}",
        out.status
    );
    assert_eq!(out.status.code(), Some(1), "stderr:\n{stderr}");
    assert!(
        stderr.contains("encryption"),
        "expected encryption diagnostic, got: {stderr}"
    );
}
