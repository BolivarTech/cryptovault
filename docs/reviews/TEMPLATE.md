# External FEC Review — `cryptovault` (SR-F5)

> **Purpose.** `cryptovault` and its FEC crates (`reedsolomon` 0.1.0,
> `viterbi` 0.0.1) share a single author. Self-consistency is **not** correctness:
> a same-author test can validate a same-author bug. This review breaks that
> correlated blind-spot with **independent eyes** on the FEC encode/decode paths.
>
> **How to use.** Copy this file to `docs/reviews/fec-<version>.signed.md`
> (matching the crate version in the root `Cargo.toml`, e.g. `fec-2.0.0.signed.md`),
> complete every item, and fill in the **Sign-off** block. The
> `xtask review-gate` command requires that signed file — with a non-empty
> `Reviewer:` and `Date:` line — before any `v<version>` release tag; a missing
> or unsigned artifact **fails the release build**.
>
> **NOT waivable.** There is no `--waive` flag: a silent escape hatch would
> defeat the very blind-spot this review exists to mitigate. A genuine waiver
> requires a documented **owner sign-off + rationale recorded in the release
> notes**, never a CLI toggle.

---

## Scope

- **Crates under review:** `reedsolomon` 0.1.0 (outer RS(255,223)),
  `viterbi` 0.0.1 (inner K=7, R=1/2 convolutional / Viterbi).
- **Version gated:** `<fill in — must match root Cargo.toml `version`>`
- **Reviewer must be independent** of the crate author for the review to satisfy
  the single-author-blind-spot mitigation.

## Independent reference vectors

The review MUST confirm correctness against vectors derived from an
**independent reference implementation** — CCSDS reference, Karn's `libfec`, or
an unrelated RS/convolutional crate — **not** the author's own crates (that would
re-introduce the circular-KAT problem). The in-repo independent vectors already
live in [`tests/kat_reference.rs`](../../tests/kat_reference.rs); confirm they
were generated independently and extend them if gaps are found.

- [ ] Independent RS reference vectors identified (source: ____________________)
- [ ] Independent Viterbi/convolutional reference vectors identified (source: ______)
- [ ] `tests/kat_reference.rs` cross-checked against the independent source

## Reed-Solomon `reedsolomon` 0.1.0 — correction capacity & boundaries

- [ ] **Correction capacity:** RS(255,223) corrects up to **16 symbol errors**
      per 255-byte codeword; verified at 0, 1, 16 (max) and 17 (must fail cleanly)
      errors.
- [ ] **Erasure/uncorrectable behavior:** an uncorrectable codeword surfaces as a
      typed error (no panic, no silent mis-correction escaping the AEAD backstop).
- [ ] **Chunk boundaries:** payloads at `223` / `446` / `447` bytes (chunk edges)
      encode/decode correctly; final-chunk zero-padding to 223 is exact.
- [ ] **Stream-length validation:** an RS stream whose length is not a positive
      multiple of 255 is rejected, never panics.
- [ ] **Empty / degenerate payload** (single 33-byte protected block) round-trips.

## Viterbi `viterbi` 0.0.1 — termination & boundaries

- [ ] **Zero-tail termination:** the `m = 6` flush-bit tail and the `2L + 2`
      byte-length relation match the crate's actual bit-packing/output (P0-3 KAT).
- [ ] **Trellis-state coverage:** a KAT suite exercises representative trellis
      states / transitions, not just a single happy path.
- [ ] **Block-cap handling:** inputs at / across the `VITERBI_CHUNK` sub-block
      boundary encode and decode consistently (chunk structure derived from length).
- [ ] **Hard-decision input format:** bit ordering / packing into the decoder is
      exactly as the crate expects (misorder must not silently mis-decode).
- [ ] **Misdecode backstop:** a Viterbi misdecode propagates to RS → AEAD tag
      failure (typed error), never silently-wrong plaintext.

## No-panic robustness (SR-R5)

- [ ] Every FEC-crate entry point on the decrypt path is gated by structural
      validation (cross-reference [`docs/no-panic.md`](../no-panic.md)).
- [ ] `cargo-fuzz` targets (`decrypt`, `unwrap`, `fec_crates`) show no reachable
      panic to the documented fuzzing bar.
- [ ] Both crates are pure-Rust `#![forbid(unsafe_code)]` → panic-only risk,
      no UB (confirmed).

## Findings

| # | Severity | Location | Description | Resolution |
|---|----------|----------|-------------|------------|
|   |          |          |             |            |

## Sign-off

By signing, the reviewer attests that the items above were examined
independently and the FEC encode/decode paths are fit for the gated release.

- **Reviewer:** `<name / identity — required, non-empty>`
- **Affiliation / independence statement:** `<how the reviewer is independent>`
- **Date:** `<YYYY-MM-DD — required, non-empty>`
- **Verdict:** `<APPROVED | APPROVED WITH CONDITIONS | REJECTED>`
- **Notes:** `<optional>`
