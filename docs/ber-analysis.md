<!-- Author: Julian Bolivar -->
<!-- Version: 1.0.0 -->
<!-- Date: 2026-07-03 -->

# BER-vs-Payload Analysis (SR-F6)

Empirical basis for the user-facing
[`RECOMMENDED_MAX_PAYLOAD`](../src/lib.rs) constant (`128 KiB`). Source harness:
[`tests/ber_analysis.rs`](../tests/ber_analysis.rs) (Task 23b).

## Why a recommended ceiling exists

FEC recovery is **all-or-nothing per blob**: the AEAD needs the *complete*
ciphertext, so a blob recovers **iff every one of its Reed-Solomon codewords
recovers**. There is no partial recovery — one uncorrectable codeword fails the
whole blob. A larger payload has more codewords, so its blob-level recovery
probability `(1 − q)^N` (with `N` codewords and per-codeword failure `q`) drops
multiplicatively with size. The recommended ceiling caps that compounding so a
single blob stays reliably recoverable; larger data should be **framed into
several `≤128 KiB` blobs**, each failing or recovering independently.

## Methodology

- **Pipeline under test:** the full concatenated FEC
  `Viterbi(interleave(RS(·)))` — hard-decision Viterbi (CCSDS K=7, R=1/2, own
  `viterbi` 0.1.0) as the inner code, a depth-5 deterministic block interleaver,
  and RS(255,223) (own `reedsolomon` 0.2.0) as the outer code.
- **Channel:** a memoryless **binary-symmetric channel (BSC)** flipping each
  coded bit independently with probability `BER`.
- **RNG:** a deterministic `xorshift64*` PRNG (fixed per-`BER` seed) so every run
  is reproducible run-to-run and across platforms — no external RNG dependence.
- **Per-codeword failure `q(BER)`** is measured directly (one 223-byte codeword
  pushed through the real encode → BSC → decode); **blob-level recovery** is
  extrapolated analytically as `(1 − q)^N`, avoiding a prohibitively expensive
  full 10 MiB Monte-Carlo sweep (per SR-F6 guidance). Codewords are treated as
  independent — the standard first-order concatenated-code approximation; the
  fixed interleaver does not change a codeword's marginal error distribution over
  a memoryless BSC.
- **Target:** a payload is "reliably recoverable" at a given `BER` when its
  blob-level recovery ≥ **99.9%**.

## Results

Blob-recovery probability `(1 − q)^N` at representative plaintext sizes (measured
`q` per row; deterministic seed):

| BSC BER | per-codeword `q` | 16 KiB | 128 KiB | 1 MiB | 10 MiB | derived ceiling |
|--------:|-----------------:|-------:|--------:|------:|-------:|----------------:|
| 0.1 %   | 0                | 1.000  | 1.000   | 1.000 | 1.000  | 10 MiB (cap)    |
| 1 %     | 0                | 1.000  | 1.000   | 1.000 | 1.000  | 10 MiB (cap)    |
| 3 %     | 0                | 1.000  | 1.000   | 1.000 | 1.000  | 10 MiB (cap)    |
| 5 %     | 0                | 1.000  | 1.000   | 1.000 | 1.000  | 10 MiB (cap)    |
| 6 %     | ≈ 8.8e-3         | 0.522  | 0.006   | 0.000 | 0.000  | 0               |
| 7 %     | ≈ 0.15           | 0.000  | 0.000   | 0.000 | 0.000  | 0               |
| 8 %     | ≈ 0.65           | 0.000  | 0.000   | 0.000 | 0.000  | 0               |
| 10 %    | ≈ 1.0            | 0.000  | 0.000   | 0.000 | 0.000  | 0               |

The concatenated code exhibits a **sharp recovery waterfall**: essentially
perfect per-codeword recovery (`q ≈ 0`) for channel BER up to **≈5%**, a steep
collapse near **≈6%**, and total loss by **≈10%**. This is the expected behavior
of a hard-decision K=7 convolutional inner code backed by RS(255,223).

## Derived recommended ceiling

At the documented **operating point of 0.5% BSC** the per-codeword failure is
effectively zero, so a blob recovers with probability ≈1.0 all the way to the
10 MiB plaintext cap. `RECOMMENDED_MAX_PAYLOAD` is nonetheless set to a
**conservative `128 KiB`**, because:

- It preserves large headroom below the ≈6% waterfall, so recovery stays ≥99.9%
  even if the real channel is noisier than the modeled operating point.
- Real channels exhibit **bursts** that a memoryless BSC understates; a smaller
  per-blob size limits the damage any single burst can do and keeps the
  all-or-nothing cliff away from realistic operating conditions.
- Framing into `≤128 KiB` blobs makes each frame independently recoverable,
  which is strictly more robust than one large blob of equal total size.

Regenerate the full table with:

```sh
cargo test --release --test ber_analysis -- --ignored --nocapture
```
