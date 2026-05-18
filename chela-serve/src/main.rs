//! `chela-serve` — localhost-only static webserver for the chela WebAssembly UI.
//!
//! Binds to `127.0.0.1` only and serves just two embedded assets (`/` and
//! `/chela.wasm`). HTTP rather than HTTPS is fine for loopback, and browsers don't
//! gate `crypto.getRandomValues` on it for `127.0.0.1`.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

const INDEX_HTML: &[u8] = include_bytes!("../assets/chela.html");

// Written by `build.rs` into `OUT_DIR` so the include path is stable across machines.
const WASM_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/chela.wasm"));

fn main() -> io::Result<()> {
    // Port 0: let the OS pick a free port so we never clash.
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;

    let html_hash = sha256_hex(INDEX_HTML);
    let wasm_hash = sha256_hex(WASM_BYTES);

    eprintln!();
    eprintln!("  chela web UI ready");
    eprintln!("  ────────────────────────────────────────────");
    eprintln!("  Open this URL in your browser:");
    eprintln!();
    eprintln!("      http://{bound}");
    eprintln!();
    eprintln!("  Listening on localhost only — no LAN exposure.");
    eprintln!("  Press Ctrl-C to stop.");
    eprintln!();
    eprintln!("  Bundle integrity (compare against the release page):");
    eprintln!("    SHA-256(chela.html) = {html_hash}");
    eprintln!("    SHA-256(chela.wasm) = {wasm_hash}");
    eprintln!("  Hashes for every release are also at");
    eprintln!("    https://github.com/SecretSplitKit/Chela/releases (SHA256SUMS).");
    eprintln!();

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                // Single-threaded accept loop: a stalled client would block all others,
                // so these timeouts are the safety net.
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
                if let Err(e) = handle(s) {
                    eprintln!("chela-serve: connection error: {e}");
                }
            }
            Err(e) => {
                eprintln!("chela-serve: accept failed: {e}");
            }
        }
    }
    Ok(())
}

/// Read the request line, route by path, write the response, hang up.
fn handle(stream: TcpStream) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Drain headers until the blank line; we don't use any of them.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let path = parse_request_path(&request_line);
    let mut writer = stream;
    match path.as_deref() {
        Some("/" | "/index.html") => {
            send_response(
                &mut writer,
                200,
                "OK",
                "text/html; charset=utf-8",
                INDEX_HTML,
            )?;
        }
        Some("/chela.wasm") => {
            send_response(&mut writer, 200, "OK", "application/wasm", WASM_BYTES)?;
        }
        _ => {
            send_response(
                &mut writer,
                404,
                "Not Found",
                "text/plain; charset=utf-8",
                b"404 not found\n",
            )?;
        }
    }
    Ok(())
}

/// Extract the path from an HTTP request line like `GET /chela.wasm HTTP/1.1\r\n`.
/// Returns `None` if the line is malformed; the caller responds with 404.
fn parse_request_path(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    if method != "GET" {
        return None;
    }
    let path = path.split('?').next().unwrap_or(path);
    Some(path.to_owned())
}

/// Lowercase hex SHA-256 of `bytes`, using the in-tree implementation (same one the
/// engine and the WASM bundle use). Operator can paste this into a hash compare tool
/// or `grep` it out of the published `SHA256SUMS` to verify the running binary's
/// embedded assets match the release.
fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut h = chela_primitives::sha256::Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn send_response(
    w: &mut TcpStream,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let header = build_response_header(code, reason, content_type, body.len());
    w.write_all(header.as_bytes())?;
    w.write_all(body)?;
    w.flush()?;
    Ok(())
}

/// Pure header-building half of `send_response` — split out so the security headers
/// can be asserted in unit tests without a real `TcpStream`.
fn build_response_header(code: u16, reason: &str, content_type: &str, body_len: usize) -> String {
    format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {body_len}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         {SECURITY_HEADERS_PREFIX}{INLINE_SCRIPT_CSP_HASHES}{SECURITY_HEADERS_SUFFIX}\
         \r\n",
    )
}

/// SHA-256 CSP hash tokens for every inline `<script>` block in `chela.html`,
/// computed at build time by `build.rs` and shipped in the CSP `script-src`
/// directive. Lets the served HTML's known-good inline script run while keeping
/// `'unsafe-inline'` off — any future XSS-introduced inline script (with a
/// different hash) is blocked by the browser.
const INLINE_SCRIPT_CSP_HASHES: &str =
    include_str!(concat!(env!("OUT_DIR"), "/csp_script_hashes.txt"));

/// Security headers emitted on every response.
///
/// - `X-Frame-Options: DENY` and `frame-ancestors 'none'` block any embedding of
///   the chela UI in an iframe / object / embed. Together they defeat a clickjacking
///   attack where an attacker page that has discovered the ephemeral port iframes the
///   recovery wizard and tricks the user into typing share words into hidden inputs.
/// - `default-src 'self'` + `script-src 'self' 'wasm-unsafe-eval' <hash(es)>` allows
///   only same-origin scripts AND our exact known-good inline script (hash pinned at
///   build time — see `INLINE_SCRIPT_CSP_HASHES`). `'wasm-unsafe-eval'` is required
///   for `WebAssembly.instantiate`. `'unsafe-inline'` is deliberately absent from
///   script-src so a future XSS regression can't inject executable JS.
/// - `style-src 'self' 'unsafe-inline'` allows the inline `<style>` block; tightening
///   this further would require extracting the CSS to a separate asset.
/// - `base-uri 'none'` and `form-action 'none'` are defense-in-depth.
/// - `Referrer-Policy: no-referrer` keeps the loopback URL out of any future outbound
///   request a regression might introduce.
const SECURITY_HEADERS_PREFIX: &str = "X-Frame-Options: DENY\r\n\
    Content-Security-Policy: default-src 'self'; \
        script-src 'self' 'wasm-unsafe-eval' ";
const SECURITY_HEADERS_SUFFIX: &str = "; \
        style-src 'self' 'unsafe-inline'; \
        img-src 'self' data:; \
        connect-src 'self'; \
        frame-ancestors 'none'; \
        base-uri 'none'; \
        form-action 'none'\r\n\
    Referrer-Policy: no-referrer\r\n";

#[cfg(test)]
mod tests {
    use super::{build_response_header, parse_request_path};

    #[test]
    fn parses_root() {
        assert_eq!(
            parse_request_path("GET / HTTP/1.1\r\n").as_deref(),
            Some("/")
        );
    }

    #[test]
    fn parses_asset_path() {
        assert_eq!(
            parse_request_path("GET /chela.wasm HTTP/1.1\r\n").as_deref(),
            Some("/chela.wasm"),
        );
    }

    #[test]
    fn strips_query_string() {
        assert_eq!(
            parse_request_path("GET /chela.wasm?v=1 HTTP/1.1\r\n").as_deref(),
            Some("/chela.wasm"),
        );
    }

    #[test]
    fn rejects_non_get() {
        assert!(parse_request_path("POST / HTTP/1.1\r\n").is_none());
        assert!(parse_request_path("DELETE /chela.wasm HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse_request_path("").is_none());
        assert!(parse_request_path("GET\r\n").is_none());
        assert!(parse_request_path("notarequest\n").is_none());
    }

    #[test]
    fn response_emits_clickjacking_protection() {
        let h = build_response_header(200, "OK", "text/html; charset=utf-8", 42);
        assert!(h.contains("\r\nX-Frame-Options: DENY\r\n"));
        assert!(h.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn response_emits_strict_csp() {
        let h = build_response_header(200, "OK", "text/html; charset=utf-8", 42);
        assert!(h.contains("Content-Security-Policy:"));
        assert!(h.contains("default-src 'self'"));
        // WASM bundle relies on WebAssembly.instantiate.
        assert!(h.contains("script-src 'self' 'wasm-unsafe-eval'"));
        // Our exact inline <script> is whitelisted by SHA-256 hash (computed by
        // build.rs) — `'unsafe-inline'` is deliberately NOT in script-src.
        assert!(h.contains("'sha256-"));
        let script_src_segment = h
            .split("script-src ")
            .nth(1)
            .and_then(|s| s.split(';').next())
            .unwrap_or("");
        assert!(
            !script_src_segment.contains("'unsafe-inline'"),
            "script-src must not contain 'unsafe-inline' (XSS containment): {script_src_segment}"
        );
        assert!(h.contains("style-src 'self' 'unsafe-inline'"));
        assert!(h.contains("base-uri 'none'"));
        assert!(h.contains("form-action 'none'"));
    }

    #[test]
    fn response_emits_referrer_policy_and_cache_control() {
        let h = build_response_header(200, "OK", "text/html; charset=utf-8", 42);
        assert!(h.contains("\r\nReferrer-Policy: no-referrer\r\n"));
        assert!(h.contains("\r\nCache-Control: no-store\r\n"));
    }

    #[test]
    fn response_header_ends_with_blank_line() {
        // Required by HTTP/1.1 to separate headers from body.
        let h = build_response_header(404, "Not Found", "text/plain", 14);
        assert!(h.ends_with("\r\n\r\n"));
    }

    #[test]
    fn security_headers_are_present_on_error_responses_too() {
        // 404 etc. must carry the same lockdown headers — otherwise an attacker
        // page could iframe an error response and still execute clickjacking on
        // the framed origin.
        let h = build_response_header(404, "Not Found", "text/plain; charset=utf-8", 14);
        assert!(h.contains("X-Frame-Options: DENY"));
        assert!(h.contains("frame-ancestors 'none'"));
    }
}
