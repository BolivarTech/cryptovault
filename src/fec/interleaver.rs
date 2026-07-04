// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Interleaving stage of the concatenated FEC (SR-F2, P0-1, P0-2).
//!
//! Interleaving reorders the Reed-Solomon symbol stream *before* the inner
//! Viterbi code so that a channel **burst** — many consecutive corrupted
//! symbols — is scattered across many RS codewords on receive, where the outer
//! `RS(255,223)` code (≤16 symbol errors per codeword) can absorb it. It is
//! **resilience, not security**: the default block interleaver uses **no key
//! material** and its permutation is public and fixed.
//!
//! # Default: deterministic block interleaver
//!
//! The stream is cut into windows of `depth` codewords (`depth * RS_BLOCK`
//! bytes). Each window is treated as a `depth`-row × [`RS_BLOCK`]-column matrix
//! filled **row by row** (row `r` = codeword `r`) and read out **column by
//! column**. Reading column-major makes consecutive transmitted symbols come
//! from consecutive rows (different codewords), so a burst is spread. De-inter-
//! leaving writes column-major and reads row-major — the exact inverse. Index
//! math only ⇒ TX and RX are byte-identical and platform-independent. The final
//! window may be short; it is permuted at its **actual length** (no padding).
//!
//! # Burst-spreading guarantee (P0-2, concrete numbers)
//!
//! **Within one full window** (`depth` codewords): a burst of ≤`depth`
//! consecutive channel symbols lands **≤1 symbol in any single RS codeword**
//! (column-major read visits `depth` distinct rows before repeating a column).
//!
//! **Across a full↔full window boundary:** a burst of ≤`depth` straddling the
//! boundary is split by the boundary into two sub-bursts, one per adjacent
//! window. Because the two windows hold **disjoint** codewords, the affected
//! codewords belong to **≤2 windows** and **each RS codeword still receives ≤1
//! burst symbol** — the within-window bound composes cleanly, so RS(255,223)
//! (16-symbol capacity) corrects it with wide margin.
//!
//! **Reduced bound at a short trailing partial window (documented caveat):** a
//! partial window holds `p < depth` codewords, so its column-major read repeats
//! a row every `p` symbols. A burst of length `b` straddling *into* such a
//! partial window may place up to `⌈b / p⌉` symbols in one of its codewords
//! (e.g. `b=depth`, `p=2` ⇒ up to 3). This is still bounded and far under the
//! 16-symbol RS capacity, but it is a weaker guarantee than the full-window
//! `≤1`. Callers who need the strict `≤1` bound everywhere should size payloads
//! so the RS stream is a whole multiple of `depth * RS_BLOCK`.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::{KEY_LEN, NONCE_LEN, RS_BLOCK, RS_INTERLEAVE_MAX};

/// Deterministic block interleaver — the default, public/fixed FEC interleaving
/// stage (SR-F2).
///
/// Spreads channel bursts across Reed-Solomon codewords using a write-row /
/// read-column block permutation over windows of `depth` codewords. Holds **no
/// key material** (it is not a security primitive); its permutation is entirely
/// determined by `depth` and the stream length, so TX and RX compute the
/// identical mapping. Construct it with [`BlockInterleaver::new`].
///
/// # Examples
///
/// ```
/// use cryptovault::fec::BlockInterleaver;
///
/// let il = BlockInterleaver::new(5).unwrap();
/// let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
/// let interleaved = il.interleave(&data);
/// assert_eq!(il.deinterleave(&interleaved), data); // exact inverse
/// ```
pub struct BlockInterleaver {
    /// Interleave depth `I`: codewords per window (validated `1..=RS_INTERLEAVE_MAX`).
    depth: usize,
}

impl BlockInterleaver {
    /// Creates a block interleaver of the given `depth` (`I`, codewords per
    /// window).
    ///
    /// # Parameters
    /// - `depth`: interleave depth in RS codewords; window span is
    ///   `depth * RS_BLOCK` bytes. `depth = 1` is a valid but degenerate
    ///   passthrough (no burst spreading); use `depth >= 2` for protection.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if `depth` is `0` or greater than
    /// [`RS_INTERLEAVE_MAX`].
    pub fn new(depth: usize) -> Result<Self> {
        if !(1..=RS_INTERLEAVE_MAX).contains(&depth) {
            return Err(CryptoError::InvalidInput(format!(
                "interleave depth {depth} out of range 1..={RS_INTERLEAVE_MAX}"
            )));
        }
        Ok(Self { depth })
    }

    /// Interleave depth `I` (codewords per window).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Window span in bytes (`depth * RS_BLOCK`).
    pub(crate) fn window_len(&self) -> usize {
        self.depth * RS_BLOCK
    }

    /// Column-major read order for a window holding `filled` bytes.
    ///
    /// Returns the input indices (relative to the window start) in the order the
    /// interleaver reads them out: for each column, every row whose cell is
    /// filled. `perm[k]` is the source index of the `k`-th output byte; it is a
    /// permutation of `0..filled`, so it drives both interleave and its inverse.
    /// `filled <= window_len` always.
    fn window_perm(&self, filled: usize) -> Vec<usize> {
        let mut perm = Vec::with_capacity(filled);
        for col in 0..RS_BLOCK {
            for row in 0..self.depth {
                let idx = row * RS_BLOCK + col;
                if idx < filled {
                    perm.push(idx);
                }
            }
        }
        perm
    }

    /// Interleaves `rs_stream`, spreading bursts across RS codewords.
    ///
    /// The inverse of [`deinterleave`](Self::deinterleave). Output length equals
    /// input length; each window is permuted independently and the final short
    /// window is permuted at its actual length.
    ///
    /// # Parameters
    /// - `rs_stream`: the Reed-Solomon symbol stream to reorder.
    ///
    /// # Returns
    /// The interleaved stream (same length as `rs_stream`).
    #[must_use]
    pub fn interleave(&self, rs_stream: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; rs_stream.len()];
        let win = self.window_len();
        let mut base = 0;
        while base < rs_stream.len() {
            let filled = (rs_stream.len() - base).min(win);
            for (k, &src) in self.window_perm(filled).iter().enumerate() {
                out[base + k] = rs_stream[base + src];
            }
            base += filled;
        }
        out
    }

    /// De-interleaves `stream`, undoing [`interleave`](Self::interleave).
    ///
    /// # Parameters
    /// - `stream`: a previously interleaved stream.
    ///
    /// # Returns
    /// The original Reed-Solomon symbol stream (same length as `stream`).
    #[must_use]
    pub fn deinterleave(&self, stream: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; stream.len()];
        let win = self.window_len();
        let mut base = 0;
        while base < stream.len() {
            let filled = (stream.len() - base).min(win);
            for (k, &dst) in self.window_perm(filled).iter().enumerate() {
                out[base + dst] = stream[base + k];
            }
            base += filled;
        }
        out
    }
}

/// Optional CSPRNG obfuscation layer — **opt-in, defense-in-depth, NON-security**
/// (SR-F2).
///
/// Applied *after* the deterministic block interleaver, it replaces each
/// window's block permutation with a keyed pseudo-random one (per-window
/// Fisher-Yates over a ChaCha20 keystream). This adds structural obfuscation
/// (gradation `fixed < CSPRNG < AEAD`) but provides **no confidentiality or
/// integrity** — the AES-256-GCM-SIV AEAD, applied first, is the sole security
/// layer. It also **weakens** the block interleaver's worst-case burst-spreading
/// guarantee; that degradation is quantified in
/// `docs/interleaver-csprng-degradation.md`.
///
/// The seed is HKDF-derived key material and is held in a
/// [`Zeroizing`]`<[u8; KEY_LEN]>` so it is wiped on drop; the per-window
/// keystream working buffer is likewise `Zeroizing`.
pub struct CsprngLayer {
    /// Key-derived seed (HKDF `cryptovault:v1:interleaver`); wiped on drop.
    seed: Zeroizing<[u8; KEY_LEN]>,
}

impl CsprngLayer {
    /// Creates the CSPRNG layer from a key-derived interleaver seed slice.
    ///
    /// Accepts the seed **by reference** and copies it into the internal
    /// [`Zeroizing`] field, so a caller need not first materialize an
    /// un-zeroized `[u8; KEY_LEN]` on the stack (L7).
    ///
    /// # Parameters
    /// - `seed`: the HKDF-derived interleaver seed, exactly [`KEY_LEN`] bytes
    ///   (never the raw AEAD key).
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if `seed` is not exactly [`KEY_LEN`] bytes.
    pub fn new(seed: &[u8]) -> Result<Self> {
        if seed.len() != KEY_LEN {
            return Err(CryptoError::InvalidInput(format!(
                "interleaver seed must be exactly {KEY_LEN} bytes"
            )));
        }
        let mut buf = Zeroizing::new([0u8; KEY_LEN]);
        buf.copy_from_slice(seed);
        Ok(Self { seed: buf })
    }

    /// Draws the next unbiased index in `0..range` from the keystream.
    ///
    /// Uses **rejection sampling** (Lemire-style bound): a `u32` keystream draw
    /// `x` is rejected when `x >= floor(2^32 / range) * range`, eliminating the
    /// modulo bias a bare `x % range` would introduce. Bytes are read
    /// little-endian so the result is identical on every platform.
    fn next_index(cipher: &mut ChaCha20, range: u32) -> u32 {
        // `range >= 1`; the multiply stays within u64 (range <= window <= 4080).
        let limit = (1u64 << 32) / u64::from(range) * u64::from(range);
        loop {
            let mut buf = Zeroizing::new([0u8; 4]);
            cipher.apply_keystream(&mut buf[..]);
            let x = u32::from_le_bytes(*buf);
            if u64::from(x) < limit {
                return x % range;
            }
        }
    }

    /// Per-window read-order permutation of `0..filled`, keyed by the seed and
    /// `window_index`.
    ///
    /// Builds an identity vector and applies a Fisher-Yates shuffle driven by the
    /// ChaCha20 keystream (key = seed, nonce = `window_index` as little-endian
    /// `u64` in the low 8 bytes). Both TX and RX derive the identical permutation
    /// from `(seed, window_index, filled)`, so the transform is byte-identical
    /// and platform-independent. `perm[k]` is the source index of the `k`-th
    /// output byte.
    pub(crate) fn window_perm(&self, filled: usize, window_index: u64) -> Vec<usize> {
        let mut perm: Vec<usize> = (0..filled).collect();
        if filled <= 1 {
            return perm;
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&window_index.to_le_bytes());
        let mut cipher = ChaCha20::new((&*self.seed).into(), (&nonce).into());
        // Fisher-Yates, high index to low: swap perm[i] with a uniform j in 0..=i.
        for i in (1..filled).rev() {
            // `i + 1 <= filled <= depth * RS_BLOCK <= 4080`, fits in u32.
            let j = Self::next_index(&mut cipher, (i + 1) as u32) as usize;
            perm.swap(i, j);
        }
        perm
    }

    /// Applies the per-window CSPRNG permutation over `stream`, windowed by
    /// `window_len` (the block interleaver's window span).
    ///
    /// Inverse of [`deinterleave`](Self::deinterleave). The final short window is
    /// permuted at its actual length.
    #[must_use]
    pub fn interleave(&self, stream: &[u8], window_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; stream.len()];
        let mut base = 0;
        let mut w = 0u64;
        while base < stream.len() {
            let filled = (stream.len() - base).min(window_len);
            for (k, &src) in self.window_perm(filled, w).iter().enumerate() {
                out[base + k] = stream[base + src];
            }
            base += filled;
            w += 1;
        }
        out
    }

    /// Undoes [`interleave`](Self::interleave) over `stream`.
    #[must_use]
    pub fn deinterleave(&self, stream: &[u8], window_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; stream.len()];
        let mut base = 0;
        let mut w = 0u64;
        while base < stream.len() {
            let filled = (stream.len() - base).min(window_len);
            for (k, &dst) in self.window_perm(filled, w).iter().enumerate() {
                out[base + dst] = stream[base + k];
            }
            base += filled;
            w += 1;
        }
        out
    }
}

/// Interleaving strategy for the concatenated FEC (SR-F2).
///
/// The **default** is [`Interleaver::Block`] — the public/fixed deterministic
/// block interleaver (no key material). [`Interleaver::BlockThenCsprng`] adds the
/// opt-in [`CsprngLayer`] on top for defense-in-depth obfuscation (still
/// non-security; weaker burst-spreading). Both variants are reversible via the
/// symmetric [`interleave`](Self::interleave) / [`deinterleave`](Self::deinterleave)
/// pair.
pub enum Interleaver {
    /// Deterministic block interleaver only (default, non-keyed).
    Block(BlockInterleaver),
    /// Block interleaver followed by the CSPRNG obfuscation layer.
    BlockThenCsprng(BlockInterleaver, CsprngLayer),
}

impl Interleaver {
    /// Interleaves `stream` under the selected strategy.
    ///
    /// Inverse of [`deinterleave`](Self::deinterleave).
    #[must_use]
    pub fn interleave(&self, stream: &[u8]) -> Vec<u8> {
        match self {
            Self::Block(block) => block.interleave(stream),
            Self::BlockThenCsprng(block, csprng) => {
                let blocked = block.interleave(stream);
                csprng.interleave(&blocked, block.window_len())
            }
        }
    }

    /// De-interleaves `stream`, undoing [`interleave`](Self::interleave).
    ///
    /// The CSPRNG layer is undone first (it is applied last on encode), then the
    /// block interleaver.
    #[must_use]
    pub fn deinterleave(&self, stream: &[u8]) -> Vec<u8> {
        match self {
            Self::Block(block) => block.deinterleave(stream),
            Self::BlockThenCsprng(block, csprng) => {
                let unshuffled = csprng.deinterleave(stream, block.window_len());
                block.deinterleave(&unshuffled)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockInterleaver, CsprngLayer, Interleaver};
    use crate::error::CryptoError;
    use crate::{KEY_LEN, RS_BLOCK, RS_INTERLEAVE_MAX};

    /// L7: `CsprngLayer::new` takes the seed by reference and validates its
    /// length — a correct-length slice constructs, a wrong-length one is rejected
    /// with `InvalidInput` (never silently padded/truncated).
    #[test]
    fn test_l7_csprng_layer_new_validates_seed_length() {
        assert!(CsprngLayer::new(&[0u8; KEY_LEN][..]).is_ok());
        assert!(matches!(
            CsprngLayer::new(&[0u8; KEY_LEN - 1][..]),
            Err(CryptoError::InvalidInput(_))
        ));
        assert!(matches!(
            CsprngLayer::new(&[0u8; KEY_LEN + 1][..]),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    /// SR-F2 / P0-1: interleave then deinterleave is the identity, including a
    /// trailing partial window (`5*RS_BLOCK + 100` is not a whole window).
    #[test]
    fn test_sr_f2_block_interleave_roundtrip_and_burst_spreading() {
        let il = BlockInterleaver::new(5).unwrap();
        let stream: Vec<u8> = (0..(5 * RS_BLOCK + 100)).map(|i| i as u8).collect();
        assert_eq!(il.deinterleave(&il.interleave(&stream)), stream);
    }

    /// SR-F2: the [`Interleaver`] strategy enum round-trips under both variants,
    /// and the CSPRNG variant actually reorders relative to block-only.
    #[test]
    fn test_sr_f2_interleaver_enum_roundtrips_both_variants() {
        let stream: Vec<u8> = (0..(5 * RS_BLOCK + 42)).map(|i| i as u8).collect();

        let block = Interleaver::Block(BlockInterleaver::new(5).unwrap());
        assert_eq!(block.deinterleave(&block.interleave(&stream)), stream);

        let combined = Interleaver::BlockThenCsprng(
            BlockInterleaver::new(5).unwrap(),
            CsprngLayer::new(&[0x5Au8; KEY_LEN]).unwrap(),
        );
        assert_eq!(combined.deinterleave(&combined.interleave(&stream)), stream);
        assert_ne!(
            combined.interleave(&stream),
            block.interleave(&stream),
            "CSPRNG variant adds obfuscation on top of the block permutation"
        );
    }

    /// SR-F2: depth `I` is validated to `1..=RS_INTERLEAVE_MAX`; `I=1` is a
    /// valid (degenerate) passthrough.
    #[test]
    fn test_sr_f2_depth_out_of_range_rejected() {
        assert!(BlockInterleaver::new(0).is_err());
        assert!(BlockInterleaver::new(RS_INTERLEAVE_MAX + 1).is_err());
        assert!(BlockInterleaver::new(1).is_ok());
    }

    /// SR-F2: `I=1` interleave is an exact passthrough (window = one codeword,
    /// column-major read of a single row is the identity).
    #[test]
    fn test_sr_f2_depth_one_is_passthrough() {
        let il = BlockInterleaver::new(1).unwrap();
        let stream: Vec<u8> = (0..(3 * RS_BLOCK)).map(|i| i as u8).collect();
        assert_eq!(il.interleave(&stream), stream);
    }

    /// P0-1 KAT: fixed input → fixed, hand-derived output bytes for the
    /// column-major block permutation (`depth=5`), plus identity handling of the
    /// final partial window at `5*RS_BLOCK + 100`.
    ///
    /// Anchor points are computed by hand from the read order `out[k] = in[idx]`
    /// where `k = col*depth + row` and `idx = row*RS_BLOCK + col`; the input
    /// byte at global index `i` is `i as u8`.
    #[test]
    fn test_p0_1_block_interleaver_kat() {
        let depth = 5usize;
        let il = BlockInterleaver::new(depth).unwrap();
        let len = 5 * RS_BLOCK + 100;
        let stream: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let out = il.interleave(&stream);

        // Full window (bytes 0..1275): out[k] value = (row*255 + col) as u8.
        // k=0 → col0,row0 → idx0    → 0
        assert_eq!(out[0], 0);
        // k=1 → col0,row1 → idx255  → 255
        assert_eq!(out[1], 255);
        // k=2 → col0,row2 → idx510  → 254
        assert_eq!(out[2], 254);
        // k=3 → col0,row3 → idx765  → 253
        assert_eq!(out[3], 253);
        // k=4 → col0,row4 → idx1020 → 252
        assert_eq!(out[4], 252);
        // k=5 → col1,row0 → idx1    → 1
        assert_eq!(out[5], 1);
        // k=6 → col1,row1 → idx256  → 0
        assert_eq!(out[6], 0);

        // Final partial window (bytes 1275..1375, 100 bytes < RS_BLOCK): only
        // row 0 is populated, so column-major read is the identity.
        let win = depth * RS_BLOCK;
        assert_eq!(&out[win..], &stream[win..]);

        // Round-trip closes the KAT.
        assert_eq!(il.deinterleave(&out), stream);
    }

    /// P0-2: a burst of ≤`depth` channel symbols straddling a full↔full window
    /// boundary lands **≤1 symbol per RS codeword**, and the affected codewords
    /// belong to **≤2 windows** (concrete cross-boundary bound).
    #[test]
    fn test_p0_2_cross_window_boundary_burst_spreads_one_per_codeword() {
        let depth = 5usize;
        let il = BlockInterleaver::new(depth).unwrap();
        // Two full windows = 10 whole codewords; boundary at depth*RS_BLOCK.
        let win = depth * RS_BLOCK;
        let stream: Vec<u8> = (0..(2 * win)).map(|i| i as u8).collect();
        let mut channel = il.interleave(&stream);

        // Inject a burst of `depth` consecutive corrupted symbols straddling the
        // transmitted window boundary (2 before it, `depth-2` after).
        let burst_start = win - 2;
        for byte in channel.iter_mut().skip(burst_start).take(depth) {
            *byte ^= 0xFF;
        }

        // De-interleave and locate the corrupted RS-stream positions.
        let recovered = il.deinterleave(&channel);
        let mut per_codeword = std::collections::HashMap::new();
        let mut windows = std::collections::HashSet::new();
        for (pos, (&r, &o)) in recovered.iter().zip(stream.iter()).enumerate() {
            if r != o {
                let codeword = pos / RS_BLOCK;
                *per_codeword.entry(codeword).or_insert(0u32) += 1;
                windows.insert(pos / win);
            }
        }

        assert_eq!(
            per_codeword.values().copied().sum::<u32>(),
            depth as u32,
            "every burst symbol is accounted for after de-interleave"
        );
        assert!(
            per_codeword.values().all(|&c| c <= 1),
            "each affected RS codeword receives ≤1 burst symbol: {per_codeword:?}"
        );
        assert!(
            windows.len() <= 2,
            "affected codewords span ≤2 interleave windows: {windows:?}"
        );
    }

    /// SR-F2 (CSPRNG layer): per-window Fisher-Yates interleave round-trips
    /// exactly, including a trailing partial window.
    #[test]
    fn test_sr_f2_csprng_layer_roundtrip() {
        let layer = CsprngLayer::new(&[0x11u8; KEY_LEN]).unwrap();
        let window_len = 5 * RS_BLOCK;
        let stream: Vec<u8> = (0..(window_len + 137)).map(|i| i as u8).collect();
        let out = layer.interleave(&stream, window_len);
        assert_eq!(layer.deinterleave(&out, window_len), stream);
    }

    /// SR-F2 (CSPRNG layer): the same seed yields the same permutation on TX and
    /// RX (deterministic, platform-independent), and it actually reorders bytes
    /// (obfuscation happened — not identity).
    #[test]
    fn test_sr_f2_csprng_layer_deterministic_and_obfuscates() {
        let seed = [0x2Au8; KEY_LEN];
        let window_len = 5 * RS_BLOCK;
        let stream: Vec<u8> = (0..window_len).map(|i| i as u8).collect();
        let a = CsprngLayer::new(&seed)
            .unwrap()
            .interleave(&stream, window_len);
        let b = CsprngLayer::new(&seed)
            .unwrap()
            .interleave(&stream, window_len);
        assert_eq!(a, b, "same seed → identical permutation");
        assert_ne!(
            a, stream,
            "CSPRNG layer must reorder (obfuscate) the window"
        );
    }

    /// SR-F2 (CSPRNG layer): a different seed yields a different permutation.
    #[test]
    fn test_sr_f2_csprng_layer_seed_sensitivity() {
        let window_len = 5 * RS_BLOCK;
        let stream: Vec<u8> = (0..window_len).map(|i| i as u8).collect();
        let a = CsprngLayer::new(&[1u8; KEY_LEN])
            .unwrap()
            .interleave(&stream, window_len);
        let b = CsprngLayer::new(&[2u8; KEY_LEN])
            .unwrap()
            .interleave(&stream, window_len);
        assert_ne!(a, b, "distinct seeds → distinct permutations");
    }

    /// P0-1 (CSPRNG KAT): a fixed seed + fixed input produces a locked golden
    /// output, pinning the ChaCha20→rejection-sampled→Fisher-Yates derivation
    /// (the wire format for the optional layer).
    #[test]
    fn test_p0_1_csprng_layer_golden_kat() {
        let layer = CsprngLayer::new(&[0x42u8; KEY_LEN]).unwrap();
        // One window of exactly RS_BLOCK bytes (single-codeword window) keeps the
        // golden vector short while exercising the full derivation.
        let window_len = RS_BLOCK;
        let stream: Vec<u8> = (0..RS_BLOCK as u32).map(|i| i as u8).collect();
        let out = layer.interleave(&stream, window_len);
        // Golden first 16 output bytes (locked; regenerated only on a deliberate
        // format change). Full round-trip below proves invertibility.
        const GOLDEN_HEAD: [u8; 16] = [
            249, 67, 112, 93, 186, 69, 114, 89, 224, 248, 92, 219, 140, 64, 91, 56,
        ];
        assert_eq!(
            &out[..16],
            &GOLDEN_HEAD,
            "CSPRNG derivation is format-locked"
        );
        assert_eq!(layer.deinterleave(&out, window_len), stream);
    }

    /// SR-F2 (CSPRNG degradation, quantified — see
    /// `docs/interleaver-csprng-degradation.md`): unlike the block interleaver's
    /// guaranteed ≤1 burst symbol per codeword, the random permutation clusters
    /// ≥2 burst symbols into one RS codeword with probability
    /// `1 - depth!/depth^depth` (≈0.96 at depth=5). This test empirically
    /// confirms the modeled bound and contrasts it with the block interleaver's 0.
    #[test]
    fn test_sr_f2_csprng_burst_clustering_matches_modeled_bound() {
        let depth = 5usize;
        let window_len = depth * RS_BLOCK;
        let layer = CsprngLayer::new(&[0x7Fu8; KEY_LEN]).unwrap();

        // Model: depth burst symbols → depth uniform codewords (balls-in-bins).
        // P(some codeword gets >=2) = 1 - depth!/depth^depth.
        let factorial: u64 = (1..=depth as u64).product();
        let total: u64 = (depth as u64).pow(depth as u32);
        let modeled_cluster_prob = 1.0 - (factorial as f64) / (total as f64);

        // Sample the permutation distribution across independent window indices.
        // 1200 trials keep the std. error (~0.006) far under the 0.05 tolerance.
        let trials = 1200u64;
        let mut clustered = 0u32;
        for w in 0..trials {
            let perm = layer.window_perm(window_len, w);
            // A depth-length channel burst at positions 0..depth lands at stream
            // positions perm[0..depth]; codeword = position / RS_BLOCK.
            let mut codewords = std::collections::HashSet::new();
            let collided = perm
                .iter()
                .take(depth)
                .any(|&pos| !codewords.insert(pos / RS_BLOCK));
            if collided {
                clustered += 1;
            }
        }
        let empirical = f64::from(clustered) / trials as f64;
        assert!(
            (empirical - modeled_cluster_prob).abs() < 0.05,
            "empirical clustering {empirical:.3} within 0.05 of modeled {modeled_cluster_prob:.3}"
        );

        // Contrast: the deterministic block interleaver guarantees 0 clustering
        // for the same depth-length burst (column-major → distinct rows).
        let mut block_cw = std::collections::HashSet::new();
        let block_no_cluster = (0..depth).all(|k| {
            let row = k % depth; // column-major inner loop is `row`
            block_cw.insert(row)
        });
        assert!(
            block_no_cluster,
            "block interleaver: depth-length burst → 0 codeword clustering"
        );
    }
}
