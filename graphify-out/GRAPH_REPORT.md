# Graph Report - cryptovault  (2026-07-05)

## Corpus Check
- 44 files · ~48,975 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 448 nodes · 809 edges · 30 communities (27 shown, 3 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 10 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `4cafb748`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 30|Community 30]]

## God Nodes (most connected - your core abstractions)
1. `CryptoVault` - 21 edges
2. `CryptoError` - 17 edges
3. `ErrorCorrection` - 14 edges
4. `ConcatenatedFec` - 13 edges
5. `encode_blob()` - 11 edges
6. `decode_blob()` - 10 edges
7. `ReedSolomonCodec` - 9 edges
8. `KeyDerivation` - 9 edges
9. `expand_aead_key()` - 9 edges
10. `random_zeroizing()` - 8 edges

## Surprising Connections (you probably didn't know these)
- `test_sr_f5_hkdf_subkey_labels_and_domain_separation()` --calls--> `expand_aead_key()`  [INFERRED]
  tests/kat.rs → src/kdf.rs
- `test_sr_f5_hkdf_subkey_labels_and_domain_separation()` --calls--> `expand_interleaver_seed()`  [INFERRED]
  tests/kat.rs → src/kdf.rs
- `test_sr_c8_secret_returns_are_zeroizing()` --calls--> `generate_salt()`  [INFERRED]
  tests/invariants.rs → src/vault.rs
- `test_sr_c8_secret_returns_are_zeroizing()` --calls--> `generate_dek()`  [INFERRED]
  tests/invariants.rs → src/vault.rs
- `variant_of()` --references--> `CryptoError`  [EXTRACTED]
  tests/adversarial.rs → src/error.rs

## Import Cycles
- 1-file cycle: `src/fec/rs.rs -> src/fec/rs.rs`
- 1-file cycle: `src/fec/viterbi.rs -> src/fec/viterbi.rs`
- 2-file cycle: `src/fec/mod.rs -> src/fec/rs.rs -> src/fec/mod.rs`

## Communities (30 total, 3 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.13
Nodes (27): Box, CryptoVault, test_c1_nofec_vault_roundtrips_via_public_api(), test_c2_public_wrap_rewrap_unwrap_chain(), test_l9_data_and_envelope_blobs_are_not_cross_decryptable(), test_m1_byte_cores_reject_wrong_length_master(), test_m3_per_vault_max_blob_len_cap_rejects_oversized_blob(), test_n2_giant_base64_rejection_message_is_generic() (+19 more)

### Community 1 - "Community 1"
Cohesion: 0.09
Nodes (26): Params, Argon2Kdf, expand_aead_key(), expand_interleaver_seed(), hkdf_expand(), KeyDerivation, owasp_params(), test_sr_c2_argon2_owasp_params_and_master_is_32_bytes() (+18 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (30): 00:26 | main, 00:41-00:55 | main, 01:08–01:20 | main, 01:32–01:57 | main, 02:30-03:07 | main, 03:21-04:12 | main, 04:27 | main, 04:36-05:04 | feat/concatenated-fec (+22 more)

### Community 3 - "Community 3"
Cohesion: 0.14
Nodes (14): ChaCha20, BlockInterleaver, CsprngLayer, Interleaver, test_p0_1_block_interleaver_kat(), test_p0_1_csprng_layer_golden_kat(), test_p0_2_cross_window_boundary_burst_spreads_one_per_codeword(), test_sr_f2_block_interleave_roundtrip_and_burst_spreading() (+6 more)

### Community 4 - "Community 4"
Cohesion: 0.05
Nodes (38): Empirical demonstration — cargo-fuzz (Task 21), Entry point → guarding gate, Local smoke run (2026-07-03, Windows 11 MSVC, nightly), No-Panic Audit — decrypt / unwrap path (SR-R5, P0-4), Reachability, Release CI gate (not run here), External FEC Review — `cryptovault` 0.1.0 (SR-F5), Findings (+30 more)

### Community 5 - "Community 5"
Cohesion: 0.11
Nodes (19): Default, ConcatenatedFec, di_stack(), ErrorCorrection, test_l12_csprng_from_master_fec_roundtrips_via_vault(), test_sc2_noisy_within_capacity_recovers_exactly(), test_sc3_corruption_beyond_capacity_is_typed_error_not_silent(), test_sr_f4_sc1_clean_channel_roundtrip_default_and_injected() (+11 more)

### Community 6 - "Community 6"
Cohesion: 0.07
Nodes (27): CcsdsViterbiDecoder, Error, build_decoder(), ceil_div(), chunk_body_lengths(), coded_nbits(), rs_len_from_body(), test_p0_3_max_blob_len_uses_per_chunk_viterbi_tail() (+19 more)

### Community 7 - "Community 7"
Cohesion: 0.08
Nodes (13): DecodeError, Display, map_decode_error(), Formatter, CryptoError, Case, small_corpus(), test_sr_r5_small_adversarial_corpus_is_typed_error_no_panic() (+5 more)

### Community 8 - "Community 8"
Cohesion: 0.17
Nodes (10): Aes256GcmSiv, Nonce, Result, Aes256GcmSivCipher, hex(), sample_nonce(), test_sr_c1_c4_aead_roundtrip_with_aad_and_tamper_detection(), test_sr_c1_nonce_is_random_and_sized() (+2 more)

### Community 9 - "Community 9"
Cohesion: 0.17
Nodes (12): ExitCode, Option, Path, PathBuf, crate_version(), has_nonempty_marker(), is_signed(), main() (+4 more)

### Community 10 - "Community 10"
Cohesion: 0.14
Nodes (13): Blob layout, cryptovault, Envelope key-wrapping (DEK/KEK), Framing is the caller's responsibility, License, MSRV, Operational contracts (the caller must honor), Out of scope (what it does NOT defend against) (+5 more)

### Community 11 - "Community 11"
Cohesion: 0.18
Nodes (11): Confirmed correct (positive assurance), Findings & remediation, HIGH, INFO, LOW, MEDIUM, Remediation plan (0.2.0), Remediation summary (0.2.0) (+3 more)

### Community 12 - "Community 12"
Cohesion: 0.35
Nodes (8): blob_recovery(), codeword_count(), per_codeword_failure(), practical_payload_ceiling(), test_sr_f6_full_sweep_report(), test_sr_f6_practical_payload_ceiling_shape_and_recommended_cap(), test_sr_f6_recommended_cap_recovers_above_target_at_operating_ber(), Xorshift64

### Community 13 - "Community 13"
Cohesion: 0.22
Nodes (8): 05:49 | main, 05:51 | main, 05:53 | main, 05:54 | main, 06:03 | main, 08:25 | main, 15:24 | main, 18:00 | main

### Community 14 - "Community 14"
Cohesion: 0.25
Nodes (7): 00:02-00:35 | fix/audit-remediation, 03:45-04:36 | fix/audit-remediation, 05:26 | main, 05:31 | main, 05:46 | main, 07:15 | 🎯 audit-remediation: 20 commits, v0.2.0 complete, 20:47 | fix/audit-remediation

### Community 15 - "Community 15"
Cohesion: 0.32
Nodes (3): rs255_data(), test_sr_f1_rs_encode_matches_reference_parity_and_corrects_within_capacity(), test_sr_f1_rs_fails_loud_beyond_capacity()

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

### Community 30 - "Community 30"
Cohesion: 0.40
Nodes (4): Context, Handoff, Next, State

## Knowledge Gaps
- **119 isolated node(s):** `Week of 2026-06-29`, `Week of 2026-06-22`, `Recent`, `State`, `Next` (+114 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `CryptoError` connect `Community 7` to `Community 0`, `Community 1`, `Community 3`, `Community 5`, `Community 6`, `Community 8`?**
  _High betweenness centrality (0.082) - this node is a cross-community bridge._
- **Why does `crate_version()` connect `Community 9` to `Community 8`, `Community 0`?**
  _High betweenness centrality (0.039) - this node is a cross-community bridge._
- **Why does `ErrorCorrection` connect `Community 5` to `Community 0`, `Community 8`, `Community 6`?**
  _High betweenness centrality (0.025) - this node is a cross-community bridge._
- **What connects `Week of 2026-06-29`, `Week of 2026-06-22`, `Recent` to the rest of the system?**
  _119 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.12579281183932348 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.08970099667774087 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.06451612903225806 - nodes in this community are weakly interconnected._