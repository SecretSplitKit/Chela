//! Print-ready HTML paper-backup template, one share per page; self-contained with no external resources.

use core::fmt::Write as _;

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use chela_engine::Share;

use crate::{format_share, BackupMeta};

/// Render a print-ready HTML document with one page per share.
///
/// # Panics
/// Panics if any share contains a word index outside `0..2048` (hand-constructed only).
#[must_use]
pub fn render_paper_html(shares: &[Share], meta: &BackupMeta<'_>) -> String {
    let mut out = String::with_capacity(8 * 1024);
    out.push_str(DOCTYPE_HEAD);
    out.push_str(STYLE);
    out.push_str("</head>\n<body>\n");

    let names_valid = meta
        .shareholder_names
        .filter(|names| names.len() == shares.len());

    for (i, share) in shares.iter().enumerate() {
        let local = BackupMeta {
            shareholder_names: names_valid,
            ..*meta
        };
        render_share_page(&mut out, share, i + 1, shares.len(), &local);
    }

    out.push_str("</body>\n</html>\n");
    out
}

/// One share, standalone HTML document (one-file-per-share / `PaperFolder` flow).
#[must_use]
pub(crate) fn render_share_card_html(share: &Share, meta: &BackupMeta<'_>) -> String {
    let mut out = String::with_capacity(4 * 1024);
    out.push_str(DOCTYPE_HEAD);
    out.push_str(STYLE);
    out.push_str("</head>\n<body>\n");
    render_share_page(&mut out, share, 1, 1, meta);
    out.push_str("</body>\n</html>\n");
    out
}

// `write!` (not `writeln!`) keeps each template fragment on one source line.
#[allow(clippy::write_with_newline, clippy::too_many_lines)]
fn render_share_page(
    out: &mut String,
    share: &Share,
    page_num: usize,
    total_pages: usize,
    meta: &BackupMeta<'_>,
) {
    let id = format!("{:02X}{:02X}", share.identifier[0], share.identifier[1]);
    let id_esc = escape(&id);

    out.push_str("<article class=\"share-page\">\n");

    // Machine-readable mirror of this card. One block per <article> so tools can
    // extract via `querySelectorAll('script.chela-share')`. type="application/json"
    // is non-executable and costs nothing CSP-wise.
    render_json_block(out, share, meta);

    // Header: backup name doubles as page title; falls back to "chela" wordmark.
    let header_title = meta
        .backup_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or("chela", |s| s);
    out.push_str("  <header class=\"share-header\">\n");
    write!(
        out,
        "    <h1 class=\"title\">{}</h1>\n",
        escape(header_title),
    )
    .expect("write to String");
    write!(
        out,
        "    <div class=\"meta\">Recovery set <strong>{id_esc}</strong></div>\n",
    )
    .expect("write to String");
    out.push_str("  </header>\n");

    // Description: one paragraph per blank-line-separated block.
    if let Some(desc) = meta.description.filter(|d| !d.trim().is_empty()) {
        out.push_str("  <section class=\"intro\">\n");
        for block in desc.split("\n\n") {
            let trimmed = block.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut first = true;
            out.push_str("    <p>");
            for line in trimmed.split('\n') {
                if !first {
                    out.push_str("<br/>");
                }
                first = false;
                out.push_str(&escape(line));
            }
            out.push_str("</p>\n");
        }
        out.push_str("  </section>\n");
    }

    // Metadata: set ID, threshold, full card code.
    let card_code = format_share(share).lines().next().unwrap_or("").to_owned();
    let card_code_esc = escape(&card_code);
    out.push_str("  <section class=\"metadata\">\n");
    out.push_str("    <dl>\n");
    write!(
        out,
        "      <dt>Recovery set</dt><dd><code>{id_esc}</code></dd>\n",
    )
    .expect("write to String");
    write!(
        out,
        "      <dt>Required to recover</dt><dd>{} of {} shares</dd>\n",
        share.threshold, share.total,
    )
    .expect("write to String");
    write!(
        out,
        "      <dt>Card code</dt><dd><code>{card_code_esc}</code></dd>\n",
    )
    .expect("write to String");
    out.push_str("    </dl>\n");
    out.push_str("  </section>\n");

    out.push_str("  <section class=\"words\">\n");
    out.push_str("    <h2>Your share words</h2>\n");
    out.push_str("    <div class=\"words-grid\">\n");
    for (idx, &word_idx) in share.word_indices.iter().enumerate() {
        let word = chela_bip39::index_to_word(word_idx).expect("share index is in 0..2048");
        let word_esc = escape(word);
        let n = idx + 1;
        write!(
            out,
            "      <div class=\"word\"><span class=\"n\">{n:>3}</span><span class=\"w\">{word_esc}</span></div>\n",
        )
        .expect("write to String");
    }
    out.push_str("    </div>\n");
    out.push_str("  </section>\n");

    // Shareholders: this holder first, then others sorted case-insensitively.
    if let Some(names) = meta.shareholder_names {
        let self_idx = usize::from(share.x).saturating_sub(1);
        let my_name = names.get(self_idx).map_or("", String::as_str);

        let mut others: Vec<&String> = names
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != self_idx)
            .map(|(_, n)| n)
            .collect();
        others.sort_by_key(|name| name.to_lowercase());

        out.push_str("  <section class=\"shareholders\">\n");
        out.push_str("    <h2>People holding shares of this secret</h2>\n");
        out.push_str("    <p class=\"you\"><span class=\"label\">You:</span> ");
        write!(out, "<strong>{}</strong></p>\n", escape(my_name)).expect("write to String");
        if !others.is_empty() {
            out.push_str("    <p class=\"others-label\">Others:</p>\n");
            out.push_str("    <ul class=\"others\">\n");
            for name in others {
                write!(out, "      <li>{}</li>\n", escape(name)).expect("write to String");
            }
            out.push_str("    </ul>\n");
        }
        out.push_str("  </section>\n");
    }

    // Recovery pointer only — detailed instructions live in RECOVERY.md so they can
    // be updated without re-printing cards.
    out.push_str("  <footer class=\"recovery\">\n");
    out.push_str("    <h2>How to recover the secret</h2>\n");
    write!(
        out,
        "    <p>Gather <strong>{}</strong> of the <strong>{}</strong> cards from set <code>{id_esc}</code>, then follow the recovery guide:</p>\n",
        share.threshold, share.total,
    )
    .expect("write to String");
    out.push_str("    <p class=\"recovery-url\"><strong>https://github.com/SecretSplitKit/Chela</strong> &rarr; <code>RECOVERY.md</code></p>\n");
    out.push_str("    <p class=\"reassurance\">If that link doesn't work years from now, search the web for <em>&ldquo;chela paper backup recovery&rdquo;</em>. Embedded structured data on this page (in the &lt;script&gt; tag at the top) preserves the share for future tools.</p>\n");
    out.push_str("  </footer>\n");

    // Plain-text form: copy-paste alternative.
    out.push_str("  <section class=\"plaintext\">\n");
    out.push_str("    <span class=\"label\">Plain-text form:</span> <code>");
    out.push_str(&escape(format_share(share).trim()));
    out.push_str("</code>\n");
    out.push_str("  </section>\n");

    let _ = (page_num, total_pages);
    out.push_str("</article>\n");
}

/// Emit a `<script type="application/json" class="chela-share">…</script>` block
/// with a machine-readable mirror of this card. Schema:
///
/// ```json
/// {
///   "type": "chela.share.v1",      // bump when fields change incompatibly
///   "card_code": "CHELA-3058-1-3-5-40",
///   "set_id": "3058",              // 4-hex-char identifier
///   "card_number": 1,              // 1..=total
///   "threshold": 3,
///   "total": 5,
///   "word_count": 40,
///   "scheme": "bip39-wordlist",
///   "payload_kind": "bip39",        // or "text"
///   "words": ["security", "moment", …],
///   "backup_name": "Alice's Ethereum wallet",   // optional
///   "description": "…",                         // optional
///   "shareholder_names": ["Alice", …]           // optional
/// }
/// ```
///
/// `card_code` + `words` round-trips through `chela_share::parse_share`.
///
/// `<` is escaped to `<` inside strings so a user-supplied `</script>` in
/// `description` / `backup_name` / `shareholder_names` can't break out of the tag.
fn render_json_block(out: &mut String, share: &Share, meta: &BackupMeta<'_>) {
    out.push_str("  <script type=\"application/json\" class=\"chela-share\">\n");
    crate::export::write_share_json_object(out, share, meta);
    out.push('\n');
    out.push_str("  </script>\n");
}

/// HTML-escape a string.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

const DOCTYPE_HEAD: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>chela — paper backup</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
"#;

const STYLE: &str = r#"<style>
  :root {
    --ink: #111;
    --rule: #222;
    --muted: #555;
    --soft: #ececec;
    --chip: #f4f4f0;
    --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    --serif: "Iowan Old Style", "Georgia", "Times New Roman", serif;
  }
  /* Print: letter, narrow margins on the page itself (the share-page below adds its
     own padding, so we keep @page tight to avoid double-margins eating the layout). */
  @page { size: letter; margin: 0.3in; }
  /* Screen: emulate a printed page so opening share-N.html in a browser shows a
     card-shaped sheet instead of text glued to the top-left corner. */
  body {
    margin: 0;
    color: var(--ink);
    font-family: var(--serif);
    font-size: 10.5pt;
    line-height: 1.4;
    background: #f4f4f0;
  }
  .share-page {
    page-break-after: always;
    max-width: 6.8in;
    margin: 1.5rem auto;
    padding: 0.45in 0.5in;
    background: #fff;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    box-sizing: border-box;
  }
  .share-page:last-of-type { page-break-after: auto; }
  /* Print: keep the same padding on the page itself so the printed sheet always has
     comfortable inner margins, regardless of what the print dialog does with @page.
     Drop the screen-only chrome (background, shadow, outer margin). */
  @media print {
    body { background: #fff; font-size: 10pt; line-height: 1.35; }
    .share-page {
      max-width: none;
      margin: 0;
      padding: 0.45in 0.55in;
      box-shadow: none;
    }
  }

  /* 1. Header (backup name doubles as page title) */
  .share-header {
    border-bottom: 1.5pt solid var(--rule);
    padding-bottom: 0.35em;
    margin-bottom: 0.6em;
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 0.3em 1.2em;
  }
  .share-header .title {
    font-family: var(--serif);
    font-weight: 700;
    font-size: 17pt;
    margin: 0;
    line-height: 1.15;
  }
  .share-header .meta {
    margin-left: auto;
    font-family: var(--mono);
    font-size: 10pt;
    color: var(--muted);
  }

  /* 2. Description */
  .intro { margin-bottom: 0.5em; }
  .intro p { margin: 0 0 0.4em 0; }
  .intro p:last-child { margin-bottom: 0; }

  /* 3. Metadata (definition list) */
  .metadata {
    margin: 0.7em 0;
    padding: 0.45em 0.7em;
    background: var(--chip);
    border: 1pt solid var(--soft);
  }
  .metadata dl {
    margin: 0;
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.15em 1em;
    font-size: 10pt;
    align-items: baseline;
  }
  .metadata dt {
    font-weight: 600;
    color: var(--muted);
  }
  .metadata dd { margin: 0; }
  .metadata code {
    font-family: var(--mono);
    font-size: 9.5pt;
    word-break: break-all;
  }

  /* 4. Word list */
  .words { margin: 0.8em 0; }
  .words h2 {
    font-size: 9.5pt;
    margin: 0 0 0.35em 0;
    color: var(--muted);
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }
  .words-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.15em 0.8em;
    border: 1pt solid var(--rule);
    padding: 0.5em 0.8em;
    font-family: var(--mono);
    font-size: 10.5pt;
  }
  .word { display: flex; align-items: baseline; gap: 0.4em; }
  .word .n {
    color: var(--muted);
    font-size: 8pt;
    width: 1.6em;
    text-align: right;
  }
  .word .w { font-weight: 600; }

  /* 5. Shareholders */
  .shareholders {
    margin: 0.7em 0;
    padding: 0.5em 0.8em;
    background: var(--chip);
    border: 1pt solid var(--soft);
  }
  .shareholders h2 {
    font-size: 9.5pt;
    margin: 0 0 0.35em 0;
    color: var(--muted);
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }
  .shareholders .you {
    margin: 0 0 0.3em 0;
    font-size: 10.5pt;
  }
  .shareholders .you .label {
    color: var(--muted);
    margin-right: 0.3em;
  }
  .shareholders .others-label {
    margin: 0.3em 0 0.15em 0;
    color: var(--muted);
    font-size: 9.5pt;
  }
  .shareholders ul.others {
    margin: 0;
    padding-left: 1.2em;
    columns: 2;
    column-gap: 1.5em;
  }
  .shareholders ul.others li {
    margin: 0.05em 0;
    break-inside: avoid;
  }

  /* 6. Instructions */
  .recovery {
    margin-top: 0.7em;
    padding-top: 0.45em;
    border-top: 1pt solid var(--rule);
  }
  .recovery h2 {
    font-size: 10.5pt;
    margin: 0 0 0.3em 0;
    font-weight: 700;
  }
  .recovery ol {
    margin: 0 0 0.4em 1.3em;
    padding: 0;
  }
  .recovery ol ul {
    margin: 0.2em 0 0.3em 1.1em;
    padding: 0;
    list-style: disc;
  }
  .recovery li {
    margin-bottom: 0.2em;
    line-height: 1.35;
  }
  .recovery ol ul li {
    margin-bottom: 0.18em;
  }
  .recovery code {
    font-family: var(--mono);
    background: var(--chip);
    padding: 0.05em 0.3em;
    border-radius: 2pt;
    font-size: 9.5pt;
  }
  .recovery p {
    margin: 0.25em 0;
  }
  .recovery .recovery-url {
    margin: 0.5em 0;
    padding: 0.4em 0.6em;
    background: var(--chip);
    border: 1pt solid var(--soft);
    font-family: var(--mono);
    font-size: 10pt;
    text-align: center;
    word-break: break-all;
  }
  .recovery .recovery-url code {
    background: none;
    padding: 0;
  }
  .recovery .reassurance {
    margin: 0.35em 0 0 0;
    color: var(--muted);
    font-style: italic;
    font-size: 9.5pt;
  }

  /* 7. Plain-text form (footer) */
  .plaintext {
    margin-top: 0.6em;
    padding-top: 0.35em;
    border-top: 1pt dotted var(--soft);
    font-size: 8pt;
    color: var(--muted);
    line-height: 1.4;
    word-break: break-all;
  }
  .plaintext .label {
    font-family: var(--serif);
    margin-right: 0.3em;
  }
  .plaintext code {
    font-family: var(--mono);
  }
</style>
"#;

#[cfg(test)]
mod tests {
    use super::render_paper_html;
    use crate::BackupMeta;
    use alloc::borrow::ToOwned;
    use chela_engine::{OutputMode, PayloadKind, Share};

    fn sample() -> Share {
        Share {
            identifier: [0xa4, 0xf7],
            scheme: OutputMode::Bip39Wordlist,
            kind: PayloadKind::Bip39,
            threshold: 3,
            total: 5,
            x: 2,
            word_indices: alloc::vec![0u16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        }
    }

    #[test]
    fn renders_each_share_as_its_own_page() {
        let s1 = sample();
        let mut s2 = sample();
        s2.x = 3;
        let html = render_paper_html(&[s1, s2], &BackupMeta::default());
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("page-break-after"));
        let pages = html.matches("class=\"share-page\"").count();
        assert_eq!(pages, 2);
        assert!(html.contains("A4F7"));
        assert!(html.contains("abandon"));
        assert!(html.contains("access"));
        // Per-card share index is intentionally NOT rendered (recipients don't need their slot number).
        assert!(!html.contains("Share <strong>2</strong>"));
        assert!(!html.contains("Share <strong>3</strong>"));
    }

    #[test]
    fn renders_required_to_recover_metadata() {
        let html = render_paper_html(&[sample()], &BackupMeta::default());
        assert!(html.contains("3 of 5 shares"));
    }

    #[test]
    fn renders_description_when_supplied() {
        let s = sample();
        let description = "First paragraph.\n\nSecond paragraph, with\na soft break inside.";
        let meta = BackupMeta {
            description: Some(description),
            ..BackupMeta::default()
        };
        let html = super::render_share_card_html(&s, &meta);
        assert!(html.contains("<p>First paragraph.</p>"));
        assert!(html.contains("Second paragraph, with<br/>a soft break inside."));
        assert!(!html.contains("This is one of"));
    }

    #[test]
    fn intro_section_omitted_when_no_description() {
        let s = sample();
        let html = super::render_share_card_html(&s, &BackupMeta::default());
        assert!(!html.contains("class=\"intro\""));
        assert!(html.contains("How to recover the secret"));
    }

    #[test]
    fn recovery_section_points_to_repo_not_inline_instructions() {
        let s = sample();
        let html = super::render_share_card_html(&s, &BackupMeta::default());
        // The "where to go" URL is on the card.
        assert!(html.contains("https://github.com/SecretSplitKit/Chela"));
        assert!(html.contains("RECOVERY.md"));
        // The detailed step-by-step list that used to be printed is GONE — those
        // instructions live in the repo now so they can be improved over time.
        assert!(
            !html.contains("Choose <strong>Recover from shares</strong>"),
            "removed: per-step instructions on the card",
        );
        assert!(
            !html.contains("Command line:"),
            "removed: command-line option on the card",
        );
    }

    #[test]
    fn embeds_json_block_with_expected_schema() {
        let s = sample();
        let html = super::render_share_card_html(&s, &BackupMeta::default());
        // The JSON block is in the document, well-formed, and marked for tooling.
        assert!(html.contains(r#"<script type="application/json" class="chela-share">"#));
        let json = extract_json_block(&html);
        assert!(json.contains(r#""type":"chela.share.v1""#));
        assert!(json.contains(r#""card_code":"CHELA-A4F7-2-3-5-12""#));
        assert!(json.contains(r#""set_id":"A4F7""#));
        assert!(json.contains(r#""card_number":2"#));
        assert!(json.contains(r#""threshold":3"#));
        assert!(json.contains(r#""total":5"#));
        assert!(json.contains(r#""word_count":12"#));
        assert!(json.contains(r#""scheme":"bip39-wordlist""#));
        assert!(json.contains(r#""payload_kind":"bip39""#));
        // First and last words from the sample
        assert!(json.contains(r#""abandon""#));
        assert!(json.contains(r#""access""#));
    }

    #[test]
    fn json_block_includes_optional_metadata_when_present() {
        let names = alloc::vec![
            "Alice".to_owned(),
            "Bob".to_owned(),
            "Carol".to_owned(),
            "Dan".to_owned(),
            "Eve".to_owned()
        ];
        let meta = BackupMeta {
            backup_name: Some("Alice's wallet"),
            description: Some("A note for the family."),
            shareholder_names: Some(&names),
        };
        let html = super::render_share_card_html(&sample(), &meta);
        let json = extract_json_block(&html);
        assert!(json.contains(r#""backup_name":"Alice's wallet""#));
        assert!(json.contains(r#""description":"A note for the family.""#));
        assert!(json.contains(r#""shareholder_names":["Alice","Bob","Carol","Dan","Eve"]"#));
    }

    #[test]
    fn json_block_escapes_script_close_tag_in_user_strings() {
        // An attacker who controls backup_name / description / shareholder_names must
        // not be able to break out of the surrounding <script> tag.
        let meta = BackupMeta {
            backup_name: Some("oops </script><script>alert(1)</script>"),
            description: Some("desc with </script> in it"),
            ..BackupMeta::default()
        };
        let html = super::render_share_card_html(&sample(), &meta);
        // The injected </script> must be escaped (no second <script> ever appears).
        let script_open_count = html.matches("<script").count();
        assert_eq!(
            script_open_count, 1,
            "exactly one <script> tag should be present; second one indicates JSON tag broke out"
        );
        // The escape form ` < ` (lowercase) is what we emit.
        assert!(html.contains(r"</script>"));
    }

    #[test]
    fn json_block_is_present_per_article_in_multi_page_doc() {
        let s1 = sample();
        let mut s2 = sample();
        s2.x = 3;
        let html = render_paper_html(&[s1, s2], &BackupMeta::default());
        // One JSON block per share — tools iterate via querySelectorAll('script.chela-share').
        let blocks = html.matches(r#"class="chela-share""#).count();
        assert_eq!(blocks, 2);
    }

    /// Pull the contents of the first `<script type="application/json" class="chela-share">`
    /// block out of an HTML document. Test-only helper.
    fn extract_json_block(html: &str) -> &str {
        let needle = r#"<script type="application/json" class="chela-share">"#;
        let after_open = html.split_once(needle).expect("script open tag").1;
        after_open
            .split_once("</script>")
            .expect("script close tag")
            .0
    }

    #[test]
    fn intro_section_omitted_when_description_is_only_whitespace() {
        let s = sample();
        let meta = BackupMeta {
            description: Some("   \n\n   "),
            ..BackupMeta::default()
        };
        let html = super::render_share_card_html(&s, &meta);
        assert!(!html.contains("class=\"intro\""));
    }

    #[test]
    fn description_html_is_escaped() {
        let s = sample();
        let meta = BackupMeta {
            description: Some("Beware <script>alert('xss')</script>"),
            ..BackupMeta::default()
        };
        let html = super::render_share_card_html(&s, &meta);
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>alert"));
    }

    #[test]
    fn renders_backup_name_as_header_title() {
        let s = sample();
        let meta = BackupMeta {
            backup_name: Some("Alice's Ethereum wallet"),
            ..BackupMeta::default()
        };
        let html = super::render_share_card_html(&s, &meta);
        assert!(html.contains("<h1 class=\"title\">Alice&#39;s Ethereum wallet</h1>"));
        // Anchor on the h1 form: `<code>chela</code>` in recovery instructions is fine.
        assert!(!html.contains("<h1 class=\"title\">chela</h1>"));
    }

    #[test]
    fn falls_back_to_chela_brand_when_no_backup_name() {
        let s = sample();
        let html = super::render_share_card_html(&s, &BackupMeta::default());
        assert!(html.contains("<h1 class=\"title\">chela</h1>"));
    }

    #[test]
    fn shareholder_block_puts_holder_first_and_omits_numbering() {
        let names = [
            "Alice".to_owned(),
            "Bob".to_owned(),
            "Carol".to_owned(),
            "Dave".to_owned(),
            "Eve".to_owned(),
        ];
        let folder = crate::render_paper_folder(
            &(1u8..=5u8)
                .map(|x| {
                    let mut s = sample();
                    s.x = x;
                    s
                })
                .collect::<alloc::vec::Vec<_>>(),
            &BackupMeta {
                shareholder_names: Some(&names),
                ..BackupMeta::default()
            },
        );
        // Share #2 (Bob) goes to file index 1.
        let bob_html = &folder.shares[1].1;
        assert!(bob_html.contains("People holding shares of this secret"));
        assert!(bob_html.contains("<span class=\"label\">You:</span>"));
        assert!(bob_html.contains("<strong>Bob</strong>"));
        assert!(bob_html.contains("<ul class=\"others\">"));
        assert!(!bob_html.contains("\u{2190} you"));
        // Shareholders section must not be numbered (only the recovery <ol> may be).
        let shareholders_section = bob_html
            .split_once("class=\"shareholders\"")
            .and_then(|(_, after)| after.split_once("</section>"))
            .map_or("", |(section, _)| section);
        assert!(!shareholders_section.contains("<ol>"));
        let bob_after_others = bob_html
            .split_once("<ul class=\"others\">")
            .map_or("", |(_, after)| after);
        assert!(!bob_after_others.contains("<li>Bob</li>"));
    }

    #[test]
    fn shareholder_table_suppressed_when_name_count_mismatches() {
        let names = ["Alice".to_owned()];
        let folder = crate::render_paper_folder(
            &(1u8..=5u8)
                .map(|x| {
                    let mut s = sample();
                    s.x = x;
                    s
                })
                .collect::<alloc::vec::Vec<_>>(),
            &BackupMeta {
                shareholder_names: Some(&names),
                ..BackupMeta::default()
            },
        );
        let html = &folder.shares[0].1;
        assert!(!html.contains("People holding shares of this secret"));
    }

    #[test]
    fn html_escapes_special_characters_in_words() {
        let escaped = super::escape("<script>&\"'");
        assert_eq!(escaped, "&lt;script&gt;&amp;&quot;&#39;");
    }
}
