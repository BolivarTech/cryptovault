# External FEC Review — `cryptovault` 0.1.0 (SR-F5)

> **Purpose.** `cryptovault` and its FEC crates (`reedsolomon` 0.1.0,
> `viterbi` 0.0.1) share a single author. Self-consistency is **not** correctness:
> a same-author test can validate a same-author bug. This review breaks that
> correlated blind-spot with **independent eyes** on the FEC encode/decode paths.
>
> **Status: TECHNICAL DRAFT — sign-off pending.** This artifact documents the
> technical basis (the in-repo independent references, KATs, correction-capacity
> and no-panic evidence) on which whoever signs will attest. The completed
> checklist items below reference concrete repository evidence; the human
> attestation in the **Sign-off** section is what remains. The
> `xtask review-gate` command requires this file to carry a non-empty
> reviewer-identity line and a non-empty review-date line — both intentionally
> left blank here, so the release gate for a `v0.1.0` tag will **fail** until a
> human signer completes and commits the Sign-off block.
>
> **NOT waivable.** There is no `--waive` flag: a silent escape hatch would
> defeat the very blind-spot this review exists to mitigate. A genuine waiver
> requires a documented **owner sign-off + rationale recorded in the release
> notes**, never a CLI toggle.

*Draft prepared: 2026-07-03. Version gated: 0.1.0 (matches root `Cargo.toml`).*

---

## Scope

- **Crates under review:** `reedsolomon` 0.1.0 (outer RS(255,223)),
  `viterbi` 0.0.1 (inner K=7, R=1/2 convolutional / Viterbi).
- **Version gated:** `0.1.0` — matches the root `Cargo.toml` `version`.
- **Reviewer must be independent** of the crate author for the review to satisfy
  the single-author-blind-spot mitigation. This is an **owner sign-off**
  (single-author project) **or** an independent reviewer.

## Independent reference vectors

The review confirms correctness against vectors derived from an **independent
reference implementation** — not the author's own crates (that would re-introduce
the circular-KAT problem). The in-repo independent vectors live in
[`tests/kat_reference.rs`](../../tests/kat_reference.rs) and
[`tests/kat.rs`](../../tests/kat.rs).

- [x] Independent RS reference vectors identified
      (source: **third-party Python `reedsolo` library**, `fcr=112, prim=0x187,
      gen=2` — the CCSDS convention; parity of the block `0..=222` pinned as
      `RS255_REF_PARITY` in `tests/kat_reference.rs`, an implementation unrelated
      to the `reedsolomon` crate under test).
- [x] Independent Viterbi/convolutional reference vectors identified
      (source: **CCSDS 131.0-B** generator polynomials `G1 = 0o171`,
      `G2 = 0o133` (G2 output inverted), MSB-first; the `K=7, R=1/2` impulse
      response `[0xBA, 0x48]` was hand-traced from the published polynomials, not
      copied from the crate).
- [x] `tests/kat_reference.rs` cross-checked against the independent source —
      the `reedsolomon` encoder produces byte-identical parity to the `reedsolo`
      reference, and the `viterbi` encoder reproduces the hand-traced CCSDS
      impulse (`test_sr_f1_rs_encode_matches_reference_parity_and_corrects_within_capacity`,
      `test_sr_f3_viterbi_matches_ccsds_impulse_and_round_trips`).

## Reed-Solomon `reedsolomon` 0.1.0 — correction capacity & boundaries

- [x] **Correction capacity:** RS(255,223) corrects up to **16 symbol errors**
      per 255-byte codeword. Verified in `tests/kat_reference.rs` /
      `tests/kat.rs`: exact recovery at 16 injected errors
      (`= RS_PARITY / 2`), and 17 errors declared uncorrectable — the syndrome
      check never mis-corrects into wrong-but-plausible data.
- [x] **Erasure/uncorrectable behavior:** 17 errors surface as
      `RsError::Uncorrectable`, mapped to a typed `CryptoError::ErrorCorrection`
      — no panic, no silent mis-correction escaping the AEAD backstop
      (`test_sr_f1_rs_fails_loud_beyond_capacity`).
- [x] **Chunk boundaries:** payloads at `223` / `446` / `447` bytes (chunk edges)
      encode/decode correctly; the final-chunk zero-padding to 223 is exact and
      the recovered stream is truncated to the derived `protected_len`
      (SC-8 boundary cases in `tests/scenarios.rs`).
- [x] **Stream-length validation:** an RS stream whose length is not a positive
      multiple of 255 is rejected as `RsError::InvalidInput` → typed
      `CryptoError::InvalidInput`, never a panic (`tests/kat_reference.rs`,
      `src/blob.rs` structural validation, gates 4/9 of `docs/no-panic.md`).
- [x] **Empty / degenerate payload** (single 33-byte protected block) round-trips
      — one RS chunk, recovers to empty plaintext (SC-8).

## Viterbi `viterbi` 0.0.1 — termination & boundaries

- [x] **Zero-tail termination:** the `m = 6` flush-bit tail and the `2L + 2`
      byte-length relation match the crate's actual bit-packing/output — pinned
      against the real `viterbi` 0.0.1 encoder in
      `test_p0_3_viterbi_termination_overhead_is_two_bytes_per_block`
      (`coded.nbits == (8L + 6) * 2`, `coded.bytes.len() == 2L + TERMINATION_OVERHEAD`,
      `TERMINATION_OVERHEAD == 2`). This drives `MAX_BLOB_LEN`.
- [x] **Trellis-state coverage:** the KAT suite (`tests/kat.rs`) exercises the
      CCSDS impulse plus multi-block clean round-trips over representative
      stream lengths, not just a single happy path.
- [x] **Block-cap handling:** inputs at / across the `VITERBI_CHUNK` sub-block
      boundary encode and decode consistently; the chunk structure is derived
      from the validated length (`src/fec/viterbi.rs`, gates 5/6 of
      `docs/no-panic.md`).
- [x] **Hard-decision input format:** bit ordering / packing into the decoder is
      exactly as the crate expects (MSB-first, byte-packed), locked by the
      impulse KAT — a misorder would fail the exact-bytes assertion.
- [x] **Misdecode backstop:** a Viterbi misdecode — even a silent one beyond KAT
      coverage — propagates to wrong RS input → RS failure/mis-correct → **AEAD
      tag failure → typed error**, never silently-wrong plaintext (SR-R6,
      `tests/scenarios.rs` corruption-beyond-capacity, gate 12 of
      `docs/no-panic.md`).

## No-panic robustness (SR-R5)

- [x] Every FEC-crate entry point on the decrypt path is enumerated and gated by
      structural validation — the 13-row entry-point → gate table in
      [`docs/no-panic.md`](../no-panic.md) (base64 cap → blob-len cap → framing
      → per-chunk length → Viterbi → cross-check → RS → header read → AEAD open).
- [x] `cargo-fuzz` targets (`decrypt`, `unwrap`, `fec_crates`) show no reachable
      panic in the local smoke run (zero crashes; see `docs/no-panic.md`). The
      `fec_crates` target drives `reedsolomon` / `viterbi` **directly, unguarded**.
      *The full release-bar sweep (≥ 24 CPU-hours or ≥ 100 M executions/target on
      Linux CI) is a separate release gate and is noted as pending there.*
- [x] Both crates are pure-Rust `#![forbid(unsafe_code)]` → panic-only risk,
      no UB (confirmed; cross-referenced in `docs/unsafe-audit.md`).

## Findings

| # | Severity | Location | Description | Resolution |
|---|----------|----------|-------------|------------|
| 1 | INFO | `fuzz/` | Release-bar fuzz sweep (≥ 24 CPU-h / ≥ 100 M execs per target) not yet run in CI; only a local smoke run (0 crashes) is recorded. | Track as a release-CI gate; not a code defect. |
| — | — | — | No correctness defect found in the technical evidence above. | — |

## Sign-off

By signing, the reviewer attests that the items above were examined
independently and the FEC encode/decode paths are fit for the gated release.

> **SIGN-OFF PENDING** — reviewer identity + date required. This is an OWNER
> sign-off (single-author project) OR an independent reviewer; the release-gate
> CI will not pass until this is filled and committed.

<!--
  To sign: fill the two fields below with a non-empty identity and date (the
  xtask review-gate matches a non-empty reviewer-identity line and review-date
  line). Leaving them blank keeps the v0.1.0 release gate red, by design.
-->

- **Reviewer:**
- **Affiliation / independence statement:**
- **Date:**
- **Verdict:**
- **Notes:**
