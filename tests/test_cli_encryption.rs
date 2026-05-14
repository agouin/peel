#![cfg(feature = "sevenz")]
//! End-to-end CLI tests for `--password-from` and the exit-code-4
//! contract documented in `internal/ENCRYPTION.md`.
//!
//! These are the highest-value tests in the CLI suite: the existing
//! in-process integration tests stuff a [`PasswordSource`] directly
//! into [`CoordinatorConfig`], so the argv-side parser (and the env /
//! file loaders behind it) had no end-to-end coverage at all. A
//! regression in [`PasswordSource::parse`], in
//! [`PasswordSource::load`]'s env / file path, or in
//! `main::password_exit_code_required`'s downcast of the error chain
//! would slip past every other test.
//!
//! All fixtures use [`build_aes_copy_sevenz`] (AES-256-CBC over a
//! `Copy` 7z folder) so the archive shape stays small (one folder,
//! tens of KiB) and the test binary spends its time on argv plumbing
//! rather than decode work.

#![cfg(unix)]

#[path = "support/mod.rs"]
mod support;

use support::mock_server::{MockRequest, MockResponse, MockServer};
use support::peel_cli::{assert_tree_exactly, peel_cmd, write_password_file};
use support::sevenz_fixtures::build_aes_copy_sevenz;
use support::work::{unique_dir, CleanupDir};

const PASSWORD: &[u8] = b"correct horse battery staple";

/// Build a tiny AES-encrypted 7z body and serve it from a fresh
/// `MockServer`. Returns `(server, url)`; the server lives as long as
/// the returned value is held.
///
/// `range_supports` keeps the handler simple — peel's 7z pipeline
/// expects `Accept-Ranges: bytes` for the trailer fetch + chunked
/// folder reads, so the handler honours `Range:` with a 206 reply.
fn aes_7z_server(files: Vec<(&'static str, Vec<u8>)>, password: &[u8]) -> (MockServer, String) {
    let body = build_aes_copy_sevenz(password, &[0x42; 16], &[0x77; 16], 8, &files);
    let server = MockServer::start(move |req: &MockRequest, _| {
        let range = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("range"))
            .and_then(|(_, v)| parse_range_header(v));
        if let Some((a, b)) = range {
            let end = (b as usize + 1).min(body.len());
            let slice = body[a as usize..end].to_vec();
            return MockResponse::Reply {
                status: 206,
                reason: "Partial Content",
                headers: vec![(
                    "Content-Range".to_string(),
                    format!("bytes {a}-{}/{}", end - 1, body.len()),
                )],
                body: slice,
            };
        }
        MockResponse::ok(body.clone())
    });
    let url = format!("{}/locked.7z", server.base_url());
    (server, url)
}

fn parse_range_header(value: &str) -> Option<(u64, u64)> {
    let after = value.strip_prefix("bytes=")?;
    let (a, b) = after.split_once('-')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

#[test]
fn env_password_source_extracts_encrypted_archive() {
    let files: Vec<(&'static str, Vec<u8>)> = vec![
        ("alpha.txt", b"hello, encrypted 7z over the CLI".to_vec()),
        (
            "nested/beta.bin",
            (0..2048u32).map(|i| (i * 3) as u8).collect(),
        ),
    ];
    let (_server, url) = aes_7z_server(files.clone(), PASSWORD);

    let work = unique_dir("enc_env");
    let _g = CleanupDir(work.clone());

    let out = peel_cmd()
        .arg(&url)
        .out_dir(&work)
        .arg("--password-from")
        .arg("env:PEEL_TEST_PASSWORD")
        .env(
            "PEEL_TEST_PASSWORD",
            std::str::from_utf8(PASSWORD).expect("UTF-8 password"),
        )
        .run();

    assert_eq!(
        out.code,
        0,
        "peel exited {}; stderr=\n{}",
        out.code,
        out.stderr_str()
    );
    let expected: Vec<(&str, &[u8])> = files.iter().map(|(n, b)| (*n, b.as_slice())).collect();
    assert_tree_exactly(&work, &expected);
}

#[test]
fn file_password_source_extracts_encrypted_archive() {
    let files: Vec<(&'static str, Vec<u8>)> =
        vec![("only.txt", b"hello from file: password source".to_vec())];
    let (_server, url) = aes_7z_server(files.clone(), PASSWORD);

    let work = unique_dir("enc_file");
    let _g = CleanupDir(work.clone());
    let pw_path = write_password_file(&work, "pw", PASSWORD);

    let out = peel_cmd()
        .arg(&url)
        .out_dir(&work)
        .arg("--password-from")
        .arg(format!("file:{}", pw_path.display()))
        .run();

    assert_eq!(
        out.code,
        0,
        "peel exited {}; stderr=\n{}",
        out.code,
        out.stderr_str()
    );
    // `pw` is the password file inside `work`; the extracted tree
    // should only contain `only.txt`. assert_tree_exactly catches
    // any stray sidecar (`.peel.part`, etc.).
    let expected: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, b)| (*n, b.as_slice()))
        .chain(std::iter::once(("pw", PASSWORD)))
        .collect();
    assert_tree_exactly(&work, &expected);
}

#[test]
fn wrong_password_exits_code_4() {
    // The headline contract from `internal/ENCRYPTION.md` §Exit codes:
    // `PasswordIncorrect` must surface as exit code 4 so scripts can
    // distinguish a retry-able password issue from a generic
    // extraction failure (code 1).
    let files: Vec<(&'static str, Vec<u8>)> = vec![("locked.txt", b"secret".to_vec())];
    let (_server, url) = aes_7z_server(files, PASSWORD);

    let work = unique_dir("enc_wrong_pw");
    let _g = CleanupDir(work.clone());
    let pw_path = write_password_file(&work, "pw", b"definitely-not-right");

    let out = peel_cmd()
        .arg(&url)
        .out_dir(&work)
        .arg("--password-from")
        .arg(format!("file:{}", pw_path.display()))
        .run();

    assert_eq!(
        out.code,
        4,
        "wrong password should surface as exit 4 per internal/ENCRYPTION.md; \
         got code={}, stderr=\n{}",
        out.code,
        out.stderr_str()
    );
}

#[test]
fn missing_password_on_encrypted_archive_exits_code_4() {
    // `PasswordMissing` and `PasswordIncorrect` share exit 4. The
    // CLI omits `--password-from` entirely on an archive that needs
    // a key; without TTY access the source defaults to no-prompt
    // semantics and the decoder surfaces `PasswordMissing`.
    let files: Vec<(&'static str, Vec<u8>)> = vec![("locked.txt", b"secret".to_vec())];
    let (_server, url) = aes_7z_server(files, PASSWORD);

    let work = unique_dir("enc_missing_pw");
    let _g = CleanupDir(work.clone());

    let out = peel_cmd().arg(&url).out_dir(&work).run();

    assert_eq!(
        out.code,
        4,
        "missing password on encrypted archive should surface as exit 4; \
         got code={}, stderr=\n{}",
        out.code,
        out.stderr_str()
    );
}

#[test]
fn password_value_does_not_appear_in_stderr() {
    // Regression gate for accidental debug-print or error-chain
    // formatting that includes the password value itself. The
    // `Password` wrapper in [src/secret.rs] zeroises on drop; this
    // test is the lightweight backstop against a future change that
    // routes the cleartext into a `tracing::debug!` or
    // `format!("{err:?}")` site that the binary writes to stderr.
    let files: Vec<(&'static str, Vec<u8>)> = vec![("hi.txt", b"the body is irrelevant".to_vec())];
    let (_server, url) = aes_7z_server(files.clone(), PASSWORD);

    let work = unique_dir("enc_no_leak");
    let _g = CleanupDir(work.clone());

    let out = peel_cmd()
        .arg(&url)
        .out_dir(&work)
        .arg("--password-from")
        .arg("env:PEEL_TEST_PASSWORD")
        .env(
            "PEEL_TEST_PASSWORD",
            std::str::from_utf8(PASSWORD).expect("UTF-8 password"),
        )
        .run();

    assert_eq!(out.code, 0, "stderr=\n{}", out.stderr_str());
    let stderr = out.stderr_str();
    let pw_str = std::str::from_utf8(PASSWORD).expect("UTF-8 password");
    assert!(
        !stderr.contains(pw_str),
        "password value leaked into stderr:\n{stderr}"
    );
    // Defence-in-depth: also ensure stdout stayed clean.
    let stdout = out.stdout_str();
    assert!(
        !stdout.contains(pw_str),
        "password value leaked into stdout:\n{stdout}"
    );
}

#[test]
fn invalid_password_source_argument_is_a_clap_error_not_exit_4() {
    // Sanity-check the boundary: a malformed `--password-from`
    // value comes back from the CLI parser as `CliError`, *not* as
    // an `EncryptionError`. Exit code must be the generic anyhow
    // error path (1), not the password-specific 4 path, so scripts
    // that key off code 4 to re-prompt don't accidentally loop on
    // a typo in the flag value.
    let work = unique_dir("enc_bad_source");
    let _g = CleanupDir(work.clone());

    let out = peel_cmd()
        .arg("https://example.invalid/nope.7z")
        .out_dir(&work)
        .arg("--password-from")
        .arg("not-a-real-scheme")
        .run();

    assert_ne!(out.code, 0, "invalid scheme should fail");
    assert_ne!(
        out.code,
        4,
        "argv-shape error must not surface as exit 4; \
         got code={}, stderr=\n{}",
        out.code,
        out.stderr_str()
    );
}
