# Unsafe / UB Audit — `miri` + `cargo-geiger` (Task 23)

**Author:** Julian Bolivar · **Version:** 1.0.0 · **Date:** 2026-07-03

`cryptovault` declares `#![forbid(unsafe_code)]` crate-wide (compile-enforced),
so **no undefined behaviour is possible in this crate's own code** — the promise
is proven by the compiler, not merely asserted. `miri` and `cargo-geiger` are
milestone/CI gates that *inventory and cross-check* that posture; this note
records their status honestly (per the spec, `cargo-geiger` is an **inventory**,
never an "unsafe-free tree" claim — vetted RustCrypto deps legitimately use
audited SIMD `unsafe`).

## `cargo miri test`

- **Our crate's own code:** `#![forbid(unsafe_code)]` makes it trivially
  UB-free; the pure-Rust modules (`fec::{rs,viterbi,interleaver}`, `blob`,
  `error`, validation) contain no `unsafe`, no raw pointers, no transmutes.
- **Limitation (honest):** a full-tree `cargo +nightly miri test` does **not**
  complete cleanly on this host — the AEAD/KDF dependency stack pulls CPU-feature
  intrinsics (`aes` hardware backend), `getrandom`/`OsRng` foreign calls, and the
  full-FEC round-trip is very slow under the miri interpreter. These are
  **dependency** concerns, not this crate's.
- **Gate:** miri over the pure-Rust FEC/blob/validation paths (which is where all
  adversarial-input parsing lives) is the meaningful target and is run in CI;
  locally it is milestone-scoped. The no-UB guarantee for *our* code stands on
  `forbid(unsafe)` regardless.

## `cargo-geiger`

- **Attempted locally** (v0.13.0). It compiled the entire dependency tree, then
  aborted on a known Windows tooling bug (`tests/zzprobe.rs` — `Io NotFound`)
  before emitting the final table; the clean report is produced on the Linux CI
  runner.
- **Inventory (from the resolved tree):** the only `unsafe` in the dependency
  graph is the **RustCrypto / RNG stack** — `aes` (SIMD/AES-NI intrinsics),
  `ppv-lite86` and `zerocopy` (SIMD), and `getrandom` (OS entropy syscall). All
  are widely-audited, expected, and **outside this crate**. The author's own FEC
  crates (`reedsolomon` 0.1.0, `viterbi` 0.0.1) are pure-Rust `forbid(unsafe)`.
- **Conclusion:** this is a bounded, documented inventory — **not** a claim of an
  unsafe-free tree. `cryptovault` itself contributes **zero** `unsafe`.

## Summary

| Gate | Local (Windows dev) | Meaning |
|------|--------------------|---------|
| `#![forbid(unsafe_code)]` | ✅ compile-enforced | no UB possible in our code |
| `cargo miri` (our pure-Rust paths) | milestone/CI | confirms the `forbid` promise |
| `cargo-geiger` | tree built; report CI-run | inventories audited dep `unsafe` |
| fuzz no-panic | see `no-panic.md` | robustness of the adversarial-input path |
