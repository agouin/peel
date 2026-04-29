//! `cargo run --example http_demo -- <URL>`
//!
//! Issues a `HEAD` followed by a `GET` of the supplied URL, prints the
//! status, the headers, and the size of the body. Doubles as the demo
//! for `docs/PLAN.md` §4 — works against both plaintext and TLS
//! servers.

use std::io::Read;
use std::process::ExitCode;

use pux::http::{Client, Url};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let url_str = match args.next() {
        Some(u) => u,
        None => {
            eprintln!("usage: http_demo <URL>");
            return ExitCode::from(2);
        }
    };

    if let Err(e) = run(&url_str) {
        eprintln!("error: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(url_str: &str) -> Result<(), String> {
    let url = Url::parse(url_str).map_err(|e| format!("invalid URL: {e}"))?;
    let client = Client::new().map_err(|e| format!("client init failed: {e}"))?;

    println!("==> HEAD {url}");
    let head = client.head(&url).map_err(|e| format!("HEAD failed: {e}"))?;
    println!("<-- {} {}", head.status.code, head.status.reason);
    for (n, v) in head.headers.iter() {
        println!("    {n}: {v}");
    }

    println!("\n==> GET {url}");
    let mut resp = client
        .get_full(&url)
        .map_err(|e| format!("GET failed: {e}"))?;
    println!("<-- {} {}", resp.status.code, resp.status.reason);
    for (n, v) in resp.headers.iter() {
        println!("    {n}: {v}");
    }

    let mut body = Vec::new();
    resp.body
        .read_to_end(&mut body)
        .map_err(|e| format!("body read failed: {e}"))?;
    println!("\nbody size: {} bytes", body.len());
    Ok(())
}
