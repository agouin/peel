//! `rar_decode_probe` — drive `RarStreamDecoder` against every entry
//! in a local RAR5 archive and report per-entry success / failure.
//!
//! Sister tool to [`examples/rar_list.rs`]. Where `rar_list` only
//! exercises the §1 framing-layer walker, this probe also feeds each
//! entry's compressed bytes through the round-one
//! [`peel::decode::rar_native::RarStreamDecoder`]. Useful for mapping
//! the decoder's current frontier when curating new fixtures: feed
//! it a freshly-`rar a`'d archive and see which entries the decoder
//! handles cleanly.
//!
//! # Usage
//!
//! ```text
//! cargo run --example rar_decode_probe -- path/to/archive.rar
//! ```
//!
//! Per entry the probe prints one line of:
//!
//! - `ok name=<name> unpacked=<n>` when decoding produces exactly the
//!   header's `unpacked_size` bytes,
//! - `mismatch name=<name> wanted=<n> got=<m>` when sizes disagree,
//! - `err name=<name> err=<diagnostic>` when `decode_step` returns an
//!   error.
//!
//! Exit status: `0` only when every non-directory entry decoded
//! cleanly and matched its `unpacked_size`. Otherwise `1`.

#![cfg(feature = "rar")]

use std::io::{Cursor, Read};

use peel::decode::rar_native::RarStreamDecoder;
use peel::decode::{DecodeStatus, StreamingDecoder};
use peel::rar::archive::walk_archive;

/// Per-entry decode budget. Same `1024` cap the §F1 resume tests use,
/// scaled up for multi-block entries: 1M `decode_step` calls is enough
/// for an entry of any plausible size while still catching a wedged
/// decoder loop.
const STEP_CAP: u32 = 1_000_000;

fn main() {
    let mut args = std::env::args_os();
    let _exec = args.next();
    let path = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: rar_decode_probe <path-to.rar>");
            std::process::exit(2);
        }
    };

    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "rar_decode_probe: failed to open {}: {e}",
                path.to_string_lossy()
            );
            std::process::exit(2);
        }
    };
    let mut bytes = Vec::new();
    if let Err(e) = file.read_to_end(&mut bytes) {
        eprintln!(
            "rar_decode_probe: failed to read {}: {e}",
            path.to_string_lossy()
        );
        std::process::exit(2);
    }

    let summary = match walk_archive(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rar_decode_probe: walk_archive: {e}");
            std::process::exit(1);
        }
    };

    println!(
        "archive: {} ({} bytes, {} entries, solid={})",
        path.to_string_lossy(),
        bytes.len(),
        summary.entries.len(),
        summary.solid,
    );

    let mut all_ok = true;
    for entry in &summary.entries {
        if entry.header.file_flags.is_directory() {
            println!("  dir   name={}", entry.header.name);
            continue;
        }
        let method = entry.header.compression.method();
        if method == 0 {
            println!(
                "  store name={} unpacked={}",
                entry.header.name, entry.header.unpacked_size
            );
            continue;
        }

        let start = entry.data_offset as usize;
        let end = start + entry.packed_size as usize;
        let bitstream = bytes[start..end].to_vec();
        let dict_capacity: usize =
            (128 * 1024usize) << entry.header.compression.dict_size_selector();

        let src: Box<dyn Read + Send> = Box::new(Cursor::new(bitstream));
        let mut decoder = match RarStreamDecoder::new(src, dict_capacity) {
            Ok(d) => d,
            Err(e) => {
                println!(
                    "  err   name={} construct={}",
                    entry.header.name,
                    short_err(&e.to_string()),
                );
                all_ok = false;
                continue;
            }
        };

        let mut out = Vec::new();
        let mut steps = 0u32;
        let result = loop {
            steps += 1;
            if steps > STEP_CAP {
                break Err(format!("step cap {STEP_CAP} exceeded"));
            }
            match decoder.decode_step(&mut out) {
                Ok(DecodeStatus::Eof) => break Ok(()),
                Ok(DecodeStatus::MoreData) => continue,
                Err(e) => {
                    let mut chain = e.to_string();
                    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(&e);
                    while let Some(s) = src {
                        chain.push_str(" | ");
                        chain.push_str(&s.to_string());
                        src = s.source();
                    }
                    break Err(short_err(&chain));
                }
            }
        };

        match result {
            Ok(()) if out.len() as u64 == entry.header.unpacked_size => {
                println!(
                    "  ok    name={} unpacked={} steps={}",
                    entry.header.name,
                    out.len(),
                    steps,
                );
            }
            Ok(()) => {
                println!(
                    "  mism  name={} wanted={} got={}",
                    entry.header.name,
                    entry.header.unpacked_size,
                    out.len(),
                );
                all_ok = false;
            }
            Err(msg) => {
                println!(
                    "  err   name={} method={} dict_cap={} err={}",
                    entry.header.name, method, dict_capacity, msg,
                );
                all_ok = false;
            }
        }
    }

    if !all_ok {
        std::process::exit(1);
    }
}

/// Trim a multi-line decode error to its first line for one-per-entry
/// output. Long stack-style chains are nice for debugging but make
/// the per-entry summary table unreadable. Set
/// `RAR_DECODE_PROBE_FULL_ERR=1` in the env to keep the whole chain.
fn short_err(msg: &str) -> String {
    if std::env::var_os("RAR_DECODE_PROBE_FULL_ERR").is_some() {
        return msg.replace('\n', " | ");
    }
    msg.lines().next().unwrap_or(msg).to_string()
}
