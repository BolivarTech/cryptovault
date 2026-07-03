# CSPRNG interleaver layer — burst-spreading degradation (SR-F2)

The optional `CsprngLayer` (opt-in, defense-in-depth, **non-security**) replaces
each interleave window's deterministic block permutation with a keyed
pseudo-random one (per-window Fisher-Yates over a ChaCha20 keystream). It buys
structural obfuscation at the cost of the block interleaver's **worst-case
burst-spreading guarantee**. This note quantifies that trade so the choice is
made on numbers, not vibes.

## Baseline: the deterministic block interleaver

For a full window of `I = depth` codewords (write-row / read-column), a channel
burst of **≤ I consecutive symbols lands at most 1 symbol in any single RS
codeword** — a *guarantee*, not a probability. RS(255,223) corrects ≤16 symbol
errors per codeword, so such a burst is corrected with wide margin. (A burst
straddling a full↔full window boundary keeps the ≤1-per-codeword bound; a burst
reaching into a short trailing partial window of `p < I` codewords relaxes to
≤⌈burst/p⌉ — see the module `//!` docs.)

## CSPRNG layer: the guarantee becomes a distribution

The random permutation destroys the column-major structure. A burst of `I`
consecutive channel symbols maps to `I` positions that are, to a good
approximation, **uniform and independent over the window's `I` codewords**
(balls-in-bins: `I` balls into `I` equally-likely bins — each codeword holds
`RS_BLOCK` of the `I·RS_BLOCK` window slots).

Let `X` = "some codeword receives ≥2 of the `I` burst symbols" (a *cluster* — the
event the block interleaver forbids outright).

```
P(all I symbols in distinct codewords) = I! / I^I
P(cluster)  = 1 − I! / I^I
E[colliding pairs] = C(I,2) · (1/I) = (I − 1) / 2
```

| depth `I` | `P(cluster)` | `E[colliding pairs]` |
|----------:|-------------:|---------------------:|
| 2         | 0.500        | 0.5                  |
| 5         | 0.9616       | 2.0                  |
| 8         | 0.9976       | 3.5                  |
| 16        | ~1.0000      | 7.5                  |

At the default `depth = 5`, a burst that the block interleaver **guarantees** to
spread ≤1 per codeword instead clusters ≥2 into one codeword **~96%** of the
time, with ~2 colliding pairs on average.

## Why this is acceptable (but off by default)

- **It is never a security regression.** Confidentiality and integrity come only
  from the AES-256-GCM-SIV AEAD applied *first*; the interleaver — block or
  CSPRNG — carries no security. Worse burst-spreading costs **channel
  resilience/availability**, never secrecy or tamper-evidence.
- **RS still has margin.** Even a fully-clustered depth-5 burst puts ≤5 symbols
  in one codeword, well under the 16-symbol RS capacity. The degradation bites
  only for larger bursts near capacity, where the block interleaver's guarantee
  is exactly what you would give up.
- **Therefore the default is `Interleaver::Block`.** The CSPRNG layer is opt-in
  (`Interleaver::BlockThenCsprng`) for callers who want obfuscation and accept
  the weaker burst bound. It also introduces the static-per-key permutation
  limitation (DC-1, spec §2).

## Verification

`test_sr_f2_csprng_burst_clustering_matches_modeled_bound` (in
`src/fec/interleaver.rs`) samples the real ChaCha20→rejection-sampling→
Fisher-Yates permutation across many window indices, injects a depth-length
burst, and asserts the empirical cluster frequency is within 0.05 of the modeled
`1 − I!/I^I`, contrasted against the block interleaver's guaranteed 0.
