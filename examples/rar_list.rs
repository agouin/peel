//! `rar_list` — `peel`'s RAR5 §1 demo.
//!
//! Reads a local RAR5 file from `argv[1]`, drives
//! [`peel::rar::archive::walk_archive`] over its bytes, and prints
//! the per-entry metadata + the archive-wide flags
//! (solid / recovery / locked) and the round-one diagnostic for any
//! unsupported feature it encounters.
//!
//! The demo is the milestone marker for `internal/PLAN_rar.md` §1: at
//! this point the wire-format layer can open a RAR5 archive and
//! describe it without invoking the (still-pending) §3 pipeline or
//! the (still-pending) §4 decoder.
//!
//! # Usage
//!
//! ```text
//! cargo run --example rar_list -- path/to/archive.rar
//! ```
//!
//! Exit status:
//!
//! - `0` on success — the entry list and archive flags are printed
//!   to stdout.
//! - `1` on archive-level errors (bad signature, RAR4 archive,
//!   multi-volume archive, encrypted archive, malformed header).
//!   The error is printed to stderr.
//! - `2` on argument errors (missing path / file IO).

use std::io::Read;

use peel::rar::archive::walk_archive;

fn main() {
    let mut args = std::env::args_os();
    let _exec = args.next();
    let path = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: rar_list <path-to.rar>");
            std::process::exit(2);
        }
    };

    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("rar_list: failed to open {}: {e}", path.to_string_lossy());
            std::process::exit(2);
        }
    };
    let mut bytes = Vec::new();
    if let Err(e) = file.read_to_end(&mut bytes) {
        eprintln!("rar_list: failed to read {}: {e}", path.to_string_lossy());
        std::process::exit(2);
    }

    match walk_archive(&bytes) {
        Ok(summary) => {
            println!(
                "archive: {} ({} bytes)",
                path.to_string_lossy(),
                bytes.len()
            );
            println!("  solid:           {}", summary.solid);
            println!("  recovery_record: {}", summary.has_recovery_record);
            println!("  locked:          {}", summary.locked);
            println!("  more_volumes:    {}", summary.eof_more_volumes);
            println!("  entries: {}", summary.entries.len());
            for (i, entry) in summary.entries.iter().enumerate() {
                let dir_marker = if entry.header.file_flags.is_directory() {
                    "/"
                } else {
                    ""
                };
                let method = entry.header.compression.method();
                let method_label = match method {
                    0 => "STORED".to_string(),
                    n => format!("RAR5 method {n}"),
                };
                println!(
                    "    [{i:3}] {name}{dir_marker} \
                     unpacked={unpacked} packed={packed} method={method_label} \
                     data_offset={data_offset}",
                    name = entry.header.name,
                    unpacked = entry.header.unpacked_size,
                    packed = entry.packed_size,
                    data_offset = entry.data_offset,
                );
            }
        }
        Err(e) => {
            eprintln!("rar_list: {e}");
            std::process::exit(1);
        }
    }
}
