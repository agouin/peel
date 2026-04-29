//! Test-only support code shared by integration tests.
//!
//! `cargo` does not auto-discover modules under `tests/support/`; each
//! integration test that needs the mock server includes this file via
//! `#[path = "support/mod.rs"] mod support;` at the top of the test
//! file.

#![allow(dead_code)] // Different integration tests use different subsets.

pub mod mock_server;
