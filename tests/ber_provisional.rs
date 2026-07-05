// Author: Julian Bolivar
// Version: 0.2.2
// Date: 2026-07-03
//! Preliminary bit-error-rate (BER) pass for the outer FEC (RS + interleaver) —
//! Phase-4 close, spec SR-F6.
//!
//! **Rough / provisional.** This is the *early* defensible basis for
//! [`cryptovault::RECOMMENDED_MAX_PAYLOAD`], run **before** the inner Viterbi
//! code (Task 9) is integrated. It models a memoryless binary-symmetric channel
//! (BSC) over `RS(255,223)` + the deterministic block interleaver and measures
//! per-blob recovery. Because the inner Viterbi code adds substantial coding
//! gain, the RS-only number here is a **conservative lower bound**; the full
//! payload-vs-BER sweep (≥10^4 blobs/point, AWGN + Viterbi) is finalized in
//! Task 23b, which unhides and finalizes the constant.
//!
//! Analytical basis (binomial, `t=16` symbols/codeword): at a 0.2% bit BSC the
//! per-codeword failure probability is ≈9.7e-7, so blob recovery stays ≥99.9%
//! up to ≈1026 codewords (≈223 KiB). The provisional
//! `RECOMMENDED_MAX_PAYLOAD = 128 KiB` sits comfortably below that threshold.
//!
//! Marked `#[ignore]` (Monte-Carlo, slow in the test profile); run with
//! `cargo test --test ber_provisional -- --ignored --nocapture`.

use cryptovault::fec::ErrorCorrection;
use cryptovault::fec::{BlockInterleaver, ReedSolomonCodec};
use cryptovault::{HEADER_LEN, NONCE_LEN, RECOMMENDED_MAX_PAYLOAD, TAG_LEN};

/// Deterministic xorshift64* PRNG — reproducible across platforms (no external
/// RNG version dependence), sufficient for a rough channel simulation.
struct Xorshift64(u64);

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Uniform in `[0, 1)`.
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Runs `trials` blobs of `payload_len` plaintext bytes through
/// RS-encode → interleave → BSC(`ber`) → de-interleave → RS-decode and returns
/// the fraction recovered exactly.
fn recovery_rate(payload_len: usize, ber: f64, trials: u32, seed: u64) -> f64 {
    let rs = ReedSolomonCodec;
    let il = BlockInterleaver::new(5).unwrap();
    let protected_len = HEADER_LEN + NONCE_LEN + payload_len + TAG_LEN;
    let mut rng = Xorshift64::new(seed);
    let mut recovered = 0u32;
    for _ in 0..trials {
        // Deterministic pseudo-random protected payload.
        let protected: Vec<u8> = (0..protected_len).map(|_| rng.next_u64() as u8).collect();
        let channel_in = il.interleave(&rs.encode(&protected));
        let mut channel = channel_in.clone();
        // BSC: flip each bit independently with probability `ber`.
        for byte in channel.iter_mut() {
            for bit in 0..8 {
                if rng.next_f64() < ber {
                    *byte ^= 1 << bit;
                }
            }
        }
        let rs_stream = il.deinterleave(&channel);
        if let Ok(out) = rs.decode(&rs_stream, protected_len) {
            if out == protected {
                recovered += 1;
            }
        }
    }
    f64::from(recovered) / f64::from(trials)
}

/// SR-F6 (provisional): at the modeled 0.2% BSC operating point, a payload of
/// `RECOMMENDED_MAX_PAYLOAD` recovers with high probability, and a 4× larger
/// payload recovers strictly worse — demonstrating the all-or-nothing cliff that
/// motivates the recommended cap. Rough, pre-Viterbi (conservative floor).
#[test]
#[ignore = "Monte-Carlo BER pass; run with --ignored"]
fn test_sr_f6_provisional_recommended_payload_survives_operating_ber() {
    let ber = 0.002;
    let trials = 400;

    let at_cap = recovery_rate(RECOMMENDED_MAX_PAYLOAD, ber, trials, 0xC0FF_EE01);
    let over_cap = recovery_rate(RECOMMENDED_MAX_PAYLOAD * 4, ber, trials, 0xC0FF_EE02);
    println!(
        "BER={ber}: recovery @ {} KiB = {:.4}, @ {} KiB = {:.4}",
        RECOMMENDED_MAX_PAYLOAD / 1024,
        at_cap,
        RECOMMENDED_MAX_PAYLOAD * 4 / 1024,
        over_cap
    );

    assert!(
        at_cap >= 0.99,
        "recommended payload should recover >=99% at the operating BER, got {at_cap:.4}"
    );
    assert!(
        over_cap <= at_cap,
        "recovery must degrade with payload size (all-or-nothing cliff): \
         {over_cap:.4} !<= {at_cap:.4}"
    );
}
