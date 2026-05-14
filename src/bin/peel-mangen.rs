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
//! re-running this binary against the source tree.
//!
//! Shape choice: a separate `[[bin]]` rather than an `[[example]]` because
//! examples are compiled as part of cargo's dev-target scope, which drags
//! every `[dev-dependencies]` entry into the build closure (including
//! `xz2` → `lzma-sys`'s C compile). A bin compiles only the deps reachable
//! from its target, so the man-page generator stays cheap to build in a
//! distro chroot. `clap_mangen` is therefore an optional normal dep gated
//! by the `man-page` feature, not a dev-dep. See `internal/PLAN_packaging.md`
//! §0.2.
//!
//! Why this isn't a `build.rs`: `peel::cli::Cli` depends on the full lib
//! (decoder registry, HTTP client config, password sources, etc.), so a
//! `build.rs` `#[path]` include can't compile it without the lib already
//! being built — a circular dep. A bin sits naturally above the lib in
//! cargo's compile order.

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
            eprintln!("peel-mangen: create_dir_all({}): {e}", parent.display());
            return ExitCode::from(1);
        }
    }

    let cmd = Cli::command();
    let man = Man::new(cmd);
    let mut buf: Vec<u8> = Vec::new();
    if let Err(e) = man.render(&mut buf) {
        eprintln!("peel-mangen: render: {e}");
        return ExitCode::from(1);
    }

    if let Err(e) = fs::write(&out, &buf) {
        eprintln!("peel-mangen: write({}): {e}", out.display());
        return ExitCode::from(1);
    }

    eprintln!("peel-mangen: wrote {} ({} bytes)", out.display(), buf.len());
    ExitCode::SUCCESS
}
