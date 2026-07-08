# Graph Report - cryptovault  (2026-07-07)

## Corpus Check
- 49 files · ~53,584 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 530 nodes · 889 edges · 39 communities (35 shown, 4 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 10 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `6983f9f8`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Community 0
- Community 1
- Community 2
- Community 3
- Community 4
- Community 5
- Community 6
- Community 7
- Community 8
- Community 9
- Community 10
- Community 11
- Community 12
- Community 13
- Community 14
- Community 15
- invariants.rs
- Community 17
- Community 18
- Community 19
- Community 20
- Community 21
- Security & Quality Audit — `cryptovault` 0.1.0
- Community 23
- Community 24
- Community 25
- Community 26
- Community 27
- Community 28
- Community 29
- Community 31
- External FEC Review — `cryptovault` 0.2.0 (SR-F5)
- External FEC Review — `cryptovault` 0.2.1 (SR-F5)
- External FEC Review — `cryptovault` 0.2.2 (SR-F5)
- today-2026-07-07.md
- today-2026-07-06.done.md

## God Nodes (most connected - your core abstractions)
1. `CryptoVault` - 35 edges
2. `ErrorCorrection` - 17 edges
3. `ConcatenatedFec` - 13 edges
4. `encode_blob()` - 11 edges
5. `decode_blob()` - 10 edges
6. `CryptoError` - 9 edges
7. `ReedSolomonCodec` - 9 edges
8. `KeyDerivation` - 9 edges
9. `expand_aead_key()` - 9 edges
10. `External FEC Review — `cryptovault` 0.3.0 (SR-F5)` - 9 edges

## Surprising Connections (you probably didn't know these)
- `test_sr_f5_hkdf_subkey_labels_and_domain_separation()` --calls--> `expand_aead_key()`  [INFERRED]
  tests/kat.rs → src/kdf.rs
- `test_sr_f5_hkdf_subkey_labels_and_domain_separation()` --calls--> `expand_interleaver_seed()`  [INFERRED]
  tests/kat.rs → src/kdf.rs
- `test_sr_c8_secret_returns_are_zeroizing()` --calls--> `generate_salt()`  [INFERRED]
  tests/invariants.rs → src/vault.rs
- `test_sr_c8_secret_returns_are_zeroizing()` --calls--> `generate_dek()`  [INFERRED]
  tests/invariants.rs → src/vault.rs
- `viterbi_only_vault()` --references--> `CryptoVault`  [EXTRACTED]
  tests/viterbi_only_fec.rs → src/vault.rs

## Import Cycles
- 1-file cycle: `src/vault.rs -> src/vault.rs`
- 1-file cycle: `src/fec/viterbi.rs -> src/fec/viterbi.rs`
- 1-file cycle: `src/fec/rs.rs -> src/fec/rs.rs`
- 2-file cycle: `src/blob.rs -> src/vault.rs -> src/blob.rs`
- 2-file cycle: `src/fec/mod.rs -> src/fec/viterbi.rs -> src/fec/mod.rs`
- 2-file cycle: `src/fec/mod.rs -> src/fec/rs.rs -> src/fec/mod.rs`

## Communities (39 total, 4 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.09
Nodes (39): Box, CryptoVault, generate_dek(), generate_salt(), NoFec, random_zeroizing(), Default, Result (+31 more)

### Community 1 - "Community 1"
Cohesion: 0.12
Nodes (22): Params, Argon2Kdf, expand_aead_key(), expand_interleaver_seed(), hkdf_expand(), KeyDerivation, owasp_params(), Result (+14 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (30): 00:26 | main, 00:41-00:55 | main, 01:08–01:20 | main, 01:32–01:57 | main, 02:30-03:07 | main, 03:21-04:12 | main, 04:27 | main, 04:36-05:04 | feat/concatenated-fec (+22 more)

### Community 3 - "Community 3"
Cohesion: 0.13
Nodes (18): ChaCha20, BlockInterleaver, CsprngLayer, Interleaver, Result, Self, Vec, Zeroizing (+10 more)

### Community 4 - "Community 4"
Cohesion: 0.33
Nodes (6): Empirical demonstration — cargo-fuzz (Task 21), Entry point → guarding gate, Local smoke run (2026-07-03, Windows 11 MSVC, nightly), No-Panic Audit — decrypt / unwrap path (SR-R5, P0-4), Reachability, Release CI gate (not run here)

### Community 5 - "Community 5"
Cohesion: 0.43
Nodes (4): recovery_rate(), Self, test_sr_f6_provisional_recommended_payload_survives_operating_ber(), Xorshift64

### Community 6 - "Community 6"
Cohesion: 0.13
Nodes (18): ceil_div(), crafted_blob_b64(), decode_blob(), encode_blob(), Result, String, Vec, test_p0_5_max_blob_len_and_b64_len_recompute_from_formula() (+10 more)

### Community 7 - "Community 7"
Cohesion: 0.10
Nodes (13): Display, Error, Formatter, CryptoError, Result, String, Case, String (+5 more)

### Community 8 - "Community 8"
Cohesion: 0.18
Nodes (13): Aes256GcmSiv, Nonce, Aes256GcmSivCipher, AuthenticatedCipher, hex(), Result, Send, Sync (+5 more)

### Community 9 - "Community 9"
Cohesion: 0.15
Nodes (14): ExitCode, Path, PathBuf, crate_version(), has_nonempty_marker(), is_signed(), main(), parse_version_line() (+6 more)

### Community 10 - "Community 10"
Cohesion: 0.11
Nodes (18): AEAD-only (no FEC), Blob layout, cryptovault, Envelope key-wrapping (DEK/KEK), Framing is the caller's responsibility, License, MSRV, Operational contracts (the caller must honor) (+10 more)

### Community 11 - "Community 11"
Cohesion: 0.11
Nodes (22): DecodeError, ConcatenatedFec, di_stack(), ErrorCorrection, Default, Result, Self, Send (+14 more)

### Community 12 - "Community 12"
Cohesion: 0.31
Nodes (9): blob_recovery(), codeword_count(), per_codeword_failure(), practical_payload_ceiling(), Self, test_sr_f6_full_sweep_report(), test_sr_f6_practical_payload_ceiling_shape_and_recommended_cap(), test_sr_f6_recommended_cap_recovers_above_target_at_operating_ber() (+1 more)

### Community 13 - "Community 13"
Cohesion: 0.13
Nodes (17): CcsdsViterbiDecoder, build_decoder(), ceil_div(), chunk_body_lengths(), coded_nbits(), rs_len_from_body(), Result, Vec (+9 more)

### Community 14 - "Community 14"
Cohesion: 0.25
Nodes (7): 00:02-00:35 | fix/audit-remediation, 03:45-04:36 | fix/audit-remediation, 05:26 | main, 05:31 | main, 05:46 | main, 07:15 | 🎯 audit-remediation: 20 commits, v0.2.0 complete, 20:47 | fix/audit-remediation

### Community 15 - "Community 15"
Cohesion: 0.15
Nodes (12): rs255_data(), Vec, test_sr_f1_rs_encode_matches_reference_parity_and_corrects_within_capacity(), test_sr_f1_rs_fails_loud_beyond_capacity(), corrupt_burst(), flip_bits(), String, test_sc1_viterbi_only_clean_channel_roundtrip() (+4 more)

### Community 16 - "invariants.rs"
Cohesion: 0.20
Nodes (5): require_zeroizing_string(), require_zeroizing_vec(), String, Vec, Zeroizing

### Community 17 - "Community 17"
Cohesion: 0.33
Nodes (5): BER-vs-Payload Analysis (SR-F6), Derived recommended ceiling, Methodology, Results, Why a recommended ceiling exists

### Community 18 - "Community 18"
Cohesion: 0.33
Nodes (5): Baseline: the deterministic block interleaver, CSPRNG interleaver layer — burst-spreading degradation (SR-F2), CSPRNG layer: the guarantee becomes a distribution, Verification, Why this is acceptable (but off by default)

### Community 19 - "Community 19"
Cohesion: 0.40
Nodes (4): `cargo-geiger`, `cargo miri test`, Summary, Unsafe / UB Audit — `miri` + `cargo-geiger` (Task 23)

### Community 20 - "Community 20"
Cohesion: 0.40
Nodes (4): 22:33 | main, 22:48-22:54 | main, 23:01 | main, 23:42 | main

### Community 21 - "Community 21"
Cohesion: 0.50
Nodes (3): Archive, Week of 2026-06-22, Week of 2026-06-29

### Community 22 - "Security & Quality Audit — `cryptovault` 0.1.0"
Cohesion: 0.18
Nodes (11): Confirmed correct (positive assurance), Findings & remediation, HIGH, INFO, LOW, MEDIUM, Remediation plan (0.2.0), Remediation summary (0.2.0) (+3 more)

### Community 27 - "Community 27"
Cohesion: 0.22
Nodes (4): corrupt_burst(), String, test_sc_2_noisy_channel_within_capacity_recovers_exact_payload(), test_sc_3_corruption_beyond_capacity_is_typed_error_never_wrong_plaintext()

### Community 28 - "Community 28"
Cohesion: 0.20
Nodes (9): External FEC Review — `cryptovault` 0.3.0 (SR-F5), Findings, Independent reference vectors, No-panic robustness (SR-R5), Reed-Solomon `reedsolomon` 0.2.0 — correction capacity & boundaries, Scope, Sign-off, Viterbi `viterbi` 0.2.0 — termination & boundaries (+1 more)

### Community 29 - "Community 29"
Cohesion: 0.22
Nodes (8): External FEC Review — `cryptovault` 0.1.0 (SR-F5), Findings, Independent reference vectors, No-panic robustness (SR-R5), Reed-Solomon `reedsolomon` 0.1.0 — correction capacity & boundaries, Scope, Sign-off, Viterbi `viterbi` 0.0.1 — termination & boundaries

### Community 31 - "Community 31"
Cohesion: 0.22
Nodes (8): 05:49 | main, 05:51 | main, 05:53 | main, 05:54 | main, 06:03 | main, 08:25 | main, 15:24 | main, 18:00 | main

### Community 32 - "External FEC Review — `cryptovault` 0.2.0 (SR-F5)"
Cohesion: 0.25
Nodes (8): External FEC Review — `cryptovault` 0.2.0 (SR-F5), Findings, Independent reference vectors, No-panic robustness (SR-R5), Reed-Solomon `reedsolomon` 0.1.0 — correction capacity & boundaries, Scope, Sign-off, Viterbi `viterbi` 0.0.1 — termination & boundaries

### Community 33 - "External FEC Review — `cryptovault` 0.2.1 (SR-F5)"
Cohesion: 0.25
Nodes (8): External FEC Review — `cryptovault` 0.2.1 (SR-F5), Findings, Independent reference vectors, No-panic robustness (SR-R5), Reed-Solomon `reedsolomon` 0.2.0 — correction capacity & boundaries, Scope, Sign-off, Viterbi `viterbi` 0.1.0 — termination & boundaries

### Community 34 - "External FEC Review — `cryptovault` 0.2.2 (SR-F5)"
Cohesion: 0.25
Nodes (8): External FEC Review — `cryptovault` 0.2.2 (SR-F5), Findings, Independent reference vectors, No-panic robustness (SR-R5), Reed-Solomon `reedsolomon` 0.2.0 — correction capacity & boundaries, Scope, Sign-off, Viterbi `viterbi` 0.2.0 — termination & boundaries

### Community 35 - "today-2026-07-07.md"
Cohesion: 0.33
Nodes (5): 15:55 | main, 22:01 | main, 22:20-23:08 | feat/viterbi-only-fec, 23:39 | main, 23:57 | main

### Community 37 - "today-2026-07-06.done.md"
Cohesion: 0.40
Nodes (4): 08:40 | main, 15:18 | main, 15:39 | main, 23:28 | main

## Knowledge Gaps
- **138 isolated node(s):** `Week of 2026-06-29`, `Week of 2026-06-22`, `23:17 | feat/viterbi-only-fec`, `Recent`, `20:31 | main` (+133 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `CryptoVault` connect `Community 0` to `Community 1`, `Community 5`, `Community 6`, `Community 7`, `Community 8`, `Community 11`, `Community 12`, `Community 15`, `invariants.rs`, `Community 27`?**
  _High betweenness centrality (0.163) - this node is a cross-community bridge._
- **Why does `ErrorCorrection` connect `Community 11` to `Community 0`, `Community 13`, `Community 6`?**
  _High betweenness centrality (0.058) - this node is a cross-community bridge._
- **Why does `CryptoError` connect `Community 7` to `Community 11`, `Community 13`?**
  _High betweenness centrality (0.028) - this node is a cross-community bridge._
- **What connects `Week of 2026-06-29`, `Week of 2026-06-22`, `23:17 | feat/viterbi-only-fec` to the rest of the system?**
  _138 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.08798076923076924 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.12473118279569892 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.06451612903225806 - nodes in this community are weakly interconnected._