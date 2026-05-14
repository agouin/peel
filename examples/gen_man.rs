//! Man page generator for the `peel` binary.
//!
//! Renders [`peel::cli::Cli`] through [`clap_mangen::Man`] and writes the
//! resulting troff to the path given as the first positional argument
//! (default: `target/man/peel.1`). The output is architecture-independent
//! text, so a single invocation in CI suffices regardless of which target
//! triple the release pipeline is building for.
//!
//! Distros pick the file up either from the release tarball (where it lives
//! at `peel-<version>-<target>/peel.1`, written by `release.yml`) or by
//! re-running this example against the source tree.
//!
//! Why an example rather than a `build.rs`: `peel::cli::Cli` depends on
//! the full lib (decoder registry, HTTP client config, password sources,
//! etc.), so a `build.rs` `#[path]` include can't compile it without the
//! lib already being built — a circular dep. An example sits naturally
//! above the lib in cargo's compile order. See `internal/PLAN_packaging.md`
//! §0.2 for the design discussion.

#![cfg(unix)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::CommandFactory;
use clap_mangen::Man;

use peel::cli::Cli;

fn main() -> ExitCode {
    let out: PathBuf = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/man/peel.1"));

    if let Some(parent) = out.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("gen_man: create_dir_all({}): {e}", parent.display());
            return ExitCode::from(1);
        }
    }

    let cmd = Cli::command();
    let man = Man::new(cmd);
    let mut buf: Vec<u8> = Vec::new();
    if let Err(e) = man.render(&mut buf) {
        eprintln!("gen_man: render: {e}");
        return ExitCode::from(1);
    }

    if let Err(e) = fs::write(&out, &buf) {
        eprintln!("gen_man: write({}): {e}", out.display());
        return ExitCode::from(1);
    }

    eprintln!("gen_man: wrote {} ({} bytes)", out.display(), buf.len());
    ExitCode::SUCCESS
}
