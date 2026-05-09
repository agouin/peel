//! Test-only support code shared by integration tests.
//!
//! `cargo` does not auto-discover modules under `tests/support/`; each
//! integration test that needs the mock server includes this file via
//! `#[path = "support/mod.rs"] mod support;` at the top of the test
//! file.

#![allow(dead_code)] // Different integration tests use different subsets.

pub mod h2c_server;
pub mod mock_server;
// Gated behind the `rar` Cargo feature: the fixture builder
// references `peel::rar::format::*`, which only exists when the
// feature is on (`docs/PLAN_rar.md` §0.5).
#[cfg(feature = "rar")]
pub mod rar_fixtures;
pub mod sevenz_fixtures;
pub mod tar_fixtures;
pub mod zip_fixtures;
