//! Entry point for the `pux` CLI.
//!
//! The actual CLI is wired up in `docs/PLAN.md` §10 (`coordinator` +
//! `cli`). Until those land, this binary is a deliberate placeholder so
//! the `pux` bin target builds and CI exercises it.

#![warn(unused, clippy::all)]

fn main() {
    println!("pux {}", env!("CARGO_PKG_VERSION"));
    println!("(MVP under construction — see docs/PLAN.md)");
}
