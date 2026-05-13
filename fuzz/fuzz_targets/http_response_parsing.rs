//! Fuzz target: HTTP response-side parsers must never panic on
//! adversarial input. Covers `parse_content_range` (the `Content-Range`
//! header), `Url::parse` (used to validate redirect `Location:` values
//! and CLI URLs), and `Url::join` (the redirect-resolution path).
//!
//! Required per `internal/ENGINEERING_STANDARDS.md` §5.2 ("HTTP response
//! parsing").

#![no_main]

use libfuzzer_sys::fuzz_target;
use peel::http::{range::parse_content_range, url::Url};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_content_range(s);
    let _ = Url::parse(s);

    // Drive `Url::join` with a stable base so the redirect-resolution
    // path is exercised on the same fuzzer-supplied string. The base
    // parse is constant input — never the source of a discovered
    // crash — so an unwrap is safe and lets the assertion noise stay
    // out of the fuzzed surface.
    // INVARIANT: literal "https://example.com/" parses; any failure
    // here would be a bug surfaced by the `Url::parse` arm above.
    let base = Url::parse("https://example.com/").unwrap();
    let _ = base.join(s);
});
