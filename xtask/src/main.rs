// Author: Julian Bolivar
// Version: 1.0.0
// Date: 2026-07-03
#![forbid(unsafe_code)]
//! `xtask` — repository automation for `cryptovault`.
//!
//! Currently exposes a single command, `review-gate`, which enforces the SR-F5
//! external-FEC-review release gate: no `v*` release tag may be cut without a
//! signed, in-repo review artifact for the FEC crates (`reedsolomon` /
//! `viterbi`). Run it from CI on every release tag.
//!
//! ```text
//! cargo run --manifest-path xtask/Cargo.toml -- review-gate
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Directory (relative to the repo root) holding review artifacts.
const REVIEWS_DIR: &str = "docs/reviews";

/// Marker line every signed artifact MUST carry (reviewer identity).
const REVIEWER_MARKER: &str = "Reviewer:";

/// Marker line every signed artifact MUST carry (review date).
const DATE_MARKER: &str = "Date:";

/// Program entry point: dispatches the requested sub-command.
///
/// # Returns
/// [`ExitCode::SUCCESS`] when the sub-command succeeds; a non-zero
/// [`ExitCode`] (failing any CI build) otherwise.
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("review-gate") => review_gate(),
        Some(other) => {
            eprintln!("xtask: unknown command `{other}`");
            print_usage();
            ExitCode::FAILURE
        }
        None => {
            print_usage();
            ExitCode::FAILURE
        }
    }
}

/// Prints the command-line usage summary to stderr.
fn print_usage() {
    eprintln!("usage: cargo run --manifest-path xtask/Cargo.toml -- <command>");
    eprintln!();
    eprintln!("commands:");
    eprintln!(
        "  review-gate   Fail (non-zero) unless a signed FEC-review artifact\n\
         \x20               `{REVIEWS_DIR}/fec-<version>.signed.md` exists for the\n\
         \x20               current crate version. NOT waivable via a flag."
    );
}

/// Enforces the SR-F5 external-FEC-review release gate.
///
/// Resolves the crate version from the repository's root `Cargo.toml`, then
/// requires a matching signed review artifact
/// (`docs/reviews/fec-<version>.signed.md`) that carries both a reviewer
/// identity and a date. The gate is **deliberately not waivable** by any flag:
/// the single-author blind-spot the external review mitigates is exactly what a
/// silent `--waive` escape hatch would defeat. A genuine waiver requires a
/// documented owner sign-off + rationale recorded in the release notes (a human
/// process), never a CLI toggle.
///
/// # Returns
/// [`ExitCode::SUCCESS`] when a valid signed artifact is present; a non-zero
/// [`ExitCode`] (failing the release build) otherwise.
fn review_gate() -> ExitCode {
    let root = match repo_root() {
        Some(root) => root,
        None => {
            eprintln!("review-gate: could not locate the repository root Cargo.toml");
            return ExitCode::FAILURE;
        }
    };

    let version = match crate_version(&root) {
        Ok(version) => version,
        Err(err) => {
            eprintln!("review-gate: {err}");
            return ExitCode::FAILURE;
        }
    };

    let artifact = root
        .join(REVIEWS_DIR)
        .join(format!("fec-{version}.signed.md"));

    match std::fs::read_to_string(&artifact) {
        Ok(contents) if is_signed(&contents) => {
            println!(
                "review-gate: OK — signed FEC review found at {}",
                artifact.display()
            );
            ExitCode::SUCCESS
        }
        Ok(_) => {
            eprintln!(
                "review-gate: FAIL — {} exists but is not a valid signed review\n\
                 \x20 it MUST contain a `{REVIEWER_MARKER}` line (reviewer identity) and a\n\
                 \x20 `{DATE_MARKER}` line (review date).",
                artifact.display()
            );
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!(
                "review-gate: FAIL — required signed FEC review is missing.\n\
                 \x20 expected: {}\n\
                 \x20 An external review of reedsolomon 0.1.0 / viterbi 0.0.1 (see\n\
                 \x20 {REVIEWS_DIR}/TEMPLATE.md) MUST be completed and signed before a\n\
                 \x20 v{version} tag. This gate is NOT waivable by a flag; a genuine\n\
                 \x20 waiver requires a documented owner sign-off + rationale in the\n\
                 \x20 release notes.",
                artifact.display()
            );
            ExitCode::FAILURE
        }
    }
}

/// Locates the repository root (the directory containing the root `Cargo.toml`).
///
/// Tries, in order: the parent of this crate's own manifest directory (xtask is
/// nested one level under the repo root), then an upward walk from the current
/// working directory. Returns `None` if no `Cargo.toml` is found.
fn repo_root() -> Option<PathBuf> {
    // xtask lives at <root>/xtask; its manifest dir's parent is the repo root.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(parent) = manifest_dir.parent() {
        if parent.join("Cargo.toml").is_file() && parent.join(REVIEWS_DIR).is_dir() {
            return Some(parent.to_path_buf());
        }
    }

    // Fallback: walk up from the current working directory.
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join("Cargo.toml").is_file() && dir.join(REVIEWS_DIR).is_dir() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Extracts the `[package]` `version` value from the root `Cargo.toml`.
///
/// A minimal, dependency-free parser: it scans for the first `version = "..."`
/// line, which under the crate's manifest layout belongs to `[package]`.
///
/// # Parameters
/// - `root`: the repository root directory.
///
/// # Returns
/// The crate version string on success.
///
/// # Errors
/// A human-readable message if the manifest cannot be read or no version line
/// is found.
fn crate_version(root: &Path) -> Result<String, String> {
    let manifest = root.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .map_err(|e| format!("cannot read {}: {e}", manifest.display()))?;

    let mut in_package = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[package]";
            continue;
        }
        if in_package {
            if let Some(version) = parse_version_line(trimmed) {
                return Ok(version);
            }
        }
    }
    Err(format!(
        "no [package] version found in {}",
        manifest.display()
    ))
}

/// Parses a `version = "X.Y.Z"` manifest line, returning the quoted value.
///
/// # Parameters
/// - `line`: a single trimmed manifest line.
///
/// # Returns
/// `Some(version)` if the line assigns `version`, else `None`.
fn parse_version_line(line: &str) -> Option<String> {
    let rest = line.strip_prefix("version")?.trim_start();
    let rest = rest.strip_prefix('=')?.trim();
    let value = rest.trim_matches('"');
    if value.is_empty() || value == rest {
        None
    } else {
        Some(value.to_string())
    }
}

/// Reports whether a review artifact carries both required signature markers.
///
/// # Parameters
/// - `contents`: the full text of the candidate artifact.
///
/// # Returns
/// `true` iff a non-empty reviewer identity and a non-empty date are present.
fn is_signed(contents: &str) -> bool {
    has_nonempty_marker(contents, REVIEWER_MARKER) && has_nonempty_marker(contents, DATE_MARKER)
}

/// Reports whether some line carries `marker` followed by non-whitespace text.
///
/// # Parameters
/// - `contents`: the text to scan.
/// - `marker`: the marker prefix (e.g. `"Reviewer:"`), matched after stripping
///   any leading Markdown emphasis / list punctuation.
///
/// # Returns
/// `true` iff at least one line has the marker followed by a non-empty value.
fn has_nonempty_marker(contents: &str, marker: &str) -> bool {
    contents.lines().any(|line| {
        let stripped = line.trim_start_matches(['-', '*', '#', '>', ' ', '\t']);
        // Tolerate Markdown bold: `**Reviewer:**`.
        let stripped = stripped.trim_start_matches('*');
        stripped
            .find(marker)
            .map(|idx| stripped[idx + marker.len()..].trim_matches(['*', ' ', '\t']))
            .is_some_and(|value| !value.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_version_under_package() {
        assert_eq!(
            parse_version_line("version = \"2.0.0\""),
            Some("2.0.0".into())
        );
        assert_eq!(
            parse_version_line("version=\"1.2.3\""),
            Some("1.2.3".into())
        );
    }

    #[test]
    fn ignores_non_version_lines() {
        assert_eq!(parse_version_line("edition = \"2021\""), None);
        assert_eq!(parse_version_line("name = \"xtask\""), None);
    }

    #[test]
    fn signed_requires_both_markers() {
        let ok = "# Review\n\nReviewer: Jane Auditor\nDate: 2026-07-03\n";
        assert!(is_signed(ok));
    }

    #[test]
    fn signed_rejects_missing_date() {
        assert!(!is_signed("Reviewer: Jane Auditor\n"));
    }

    #[test]
    fn signed_rejects_empty_reviewer() {
        assert!(!is_signed("Reviewer:\nDate: 2026-07-03\n"));
    }

    #[test]
    fn signed_tolerates_markdown_bold_and_bullets() {
        let md = "- **Reviewer:** Jane Auditor\n- **Date:** 2026-07-03\n";
        assert!(is_signed(md));
    }
}
