//! Entry point for the `peel` CLI.
//!
//! The actual CLI is wired up in `docs/PLAN.md` §10 (`coordinator` +
//! `cli`). Until those land, this binary is a deliberate placeholder so
//! the `peel` bin target builds and CI exercises it.

#![warn(unused, clippy::all)]

fn main() {
    println!("peel {}", env!("CARGO_PKG_VERSION"));
    println!("(MVP under construction — see docs/PLAN.md)");
}
