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

use crate::error::{CryptoError, Result};
use crate::{RS_BLOCK, RS_INTERLEAVE_MAX};

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
    fn window_len(&self) -> usize {
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

#[cfg(test)]
mod tests {
    use super::BlockInterleaver;
    use crate::{RS_BLOCK, RS_INTERLEAVE_MAX};

    /// SR-F2 / P0-1: interleave then deinterleave is the identity, including a
    /// trailing partial window (`5*RS_BLOCK + 100` is not a whole window).
    #[test]
    fn test_sr_f2_block_interleave_roundtrip_and_burst_spreading() {
        let il = BlockInterleaver::new(5).unwrap();
        let stream: Vec<u8> = (0..(5 * RS_BLOCK + 100)).map(|i| i as u8).collect();
        assert_eq!(il.deinterleave(&il.interleave(&stream)), stream);
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
}
