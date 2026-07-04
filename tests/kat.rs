// Author: Julian Bolivar
// Version: 0.2.0
// Date: 2026-07-03
//! Task 22 — Known-Answer Tests (SR-F5): fixed vectors asserting **exact bytes**.
//!
//! Every test locks a primitive or a wire-format stage against a *reference*
//! value — official IETF/CCSDS vectors where they exist, and an independent
//! third-party reference otherwise — never a value read back out of the crate
//! under test. A mismatch here means a primitive is mis-wired (a critical bug),
//! not a flaky test.
//!
//! # Reference provenance
//!
//! * **AES-256-GCM-SIV** — RFC 8452 Appendix C.2 (the four leading vectors).
//! * **Argon2id** — RFC 9106 Section 5.3 (validated through the `argon2` crate
//!   directly, exercising the exact primitive the vault wires).
//! * **HKDF-SHA256** — RFC 5869 Appendix A.1 Test Case 1 (through the `hkdf`
//!   crate); the crate's `expand_*` helpers are then cross-checked against an
//!   in-test HKDF reference to confirm their `info` labels + `salt = None`.
//! * **RS(255,223)** — the 32 parity bytes of the block `0..=222` as produced by
//!   the third-party Python `reedsolo` library (`fcr=112, prim=0x187, gen=2`,
//!   the CCSDS convention) — an implementation unrelated to the `reedsolomon`
//!   crate under test.
//! * **Viterbi K=7 R=1/2** — the CCSDS 131.0-B impulse response `[0xBA, 0x48]`
//!   derived from the generator polynomials `G1 = 0o171`, `G2 = 0o133`
//!   (G2 inverted), MSB-first.
//! * **Interleavers** — hand-derived block permutation anchors and a locked
//!   CSPRNG golden vector (the wire format for the optional layer).

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use cryptovault::cipher::{Aes256GcmSivCipher, AuthenticatedCipher};
use cryptovault::fec::{BlockInterleaver, CsprngLayer, ReedSolomonCodec};
use cryptovault::fec::{ErrorCorrection, ViterbiCodec};
use cryptovault::kdf::{expand_aead_key, expand_interleaver_seed};
use cryptovault::{KEY_LEN, RS_BLOCK, RS_DATA, RS_PARITY};

/// Decodes a compact hex string (whitespace ignored) into bytes so the RFC
/// vectors can be pasted close to verbatim.
fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(s.len() % 2 == 0, "hex string must have an even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

// ---------------------------------------------------------------------------
// AES-256-GCM-SIV — RFC 8452 Appendix C.2 (official vectors).
// ---------------------------------------------------------------------------

/// SR-F5 / SR-C1: the four leading RFC 8452 Appendix C.2 AEAD_AES_256_GCM_SIV
/// vectors (empty→16-byte plaintext, empty AAD) reproduce the exact
/// `ciphertext ‖ tag`, and each decrypts back to its plaintext. Locks the AEAD
/// primitive against the official IETF known answers.
#[test]
fn test_sr_f5_rfc8452_aes256gcmsiv_official_vectors() {
    // Shared key/nonce across the four Appendix C.2 vectors.
    let key = hex("0100000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex("030000000000000000000000");
    let aad: &[u8] = &[];

    // (plaintext, expected ciphertext ‖ tag) — RFC 8452 C.2.
    let vectors: [(&str, &str); 4] = [
        ("", "07f5f4169bbf55a8400cd47ea6fd400f"),
        (
            "0100000000000000",
            "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
        ),
        (
            "010000000000000000000000",
            "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e",
        ),
        (
            "01000000000000000000000000000000",
            "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
        ),
    ];

    let cipher = Aes256GcmSivCipher;
    for (pt_hex, expected_hex) in vectors {
        let pt = hex(pt_hex);
        let expected = hex(expected_hex);
        let ct = cipher.encrypt(&key, &nonce, aad, &pt).unwrap();
        assert_eq!(
            ct, expected,
            "RFC 8452 C.2: ciphertext‖tag mismatch for pt={pt_hex}"
        );
        assert_eq!(
            cipher.decrypt(&key, &nonce, aad, &ct).unwrap(),
            pt,
            "RFC 8452 C.2: decrypt must recover the plaintext for pt={pt_hex}"
        );
    }
}

/// SR-F5 / SR-C4: the RFC 8452 Appendix C.2 vector *with* non-empty AAD
/// reproduces the exact `ciphertext ‖ tag`, confirming the AAD is folded into
/// the tag exactly as the standard specifies.
#[test]
fn test_sr_f5_rfc8452_aes256gcmsiv_with_aad_vector() {
    let key = hex("0100000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex("030000000000000000000000");
    // RFC 8452 C.2 (with AAD): AAD = 01000000000000000000000000000000 02000000
    let aad = hex("0100000000000000000000000000000002000000");
    let pt = hex("030000000000000000000000000000000400");
    let expected = hex("462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc2056543");

    let cipher = Aes256GcmSivCipher;
    let ct = cipher.encrypt(&key, &nonce, &aad, &pt).unwrap();
    assert_eq!(
        ct, expected,
        "RFC 8452 C.2 (with AAD): ciphertext‖tag mismatch"
    );
    assert_eq!(cipher.decrypt(&key, &nonce, &aad, &ct).unwrap(), pt);
}

// ---------------------------------------------------------------------------
// Argon2id — RFC 9106 Section 5.3 (official vector).
// ---------------------------------------------------------------------------

/// SR-F5 / SR-C2: the RFC 9106 Section 5.3 Argon2id test vector (password/salt/
/// secret/associated-data at `m=32 KiB, t=3, p=4, taglen=32`) reproduces the
/// exact 32-byte tag through the `argon2` crate the vault depends on — locking
/// the memory-hard KDF primitive against the official known answer.
#[test]
fn test_sr_f5_rfc9106_argon2id_official_vector() {
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = [0x03u8; 8];
    let associated = [0x04u8; 12];
    let expected = hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");

    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&associated).unwrap())
        .build()
        .unwrap();
    let argon = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
        .expect("valid Argon2id context");
    let mut out = [0u8; 32];
    argon
        .hash_password_into(&password, &salt, &mut out)
        .unwrap();
    assert_eq!(
        out.as_slice(),
        expected.as_slice(),
        "RFC 9106 §5.3 Argon2id tag mismatch"
    );
}

// (SR-F5 Argon2 OWASP-params pinning test moved to `src/kdf.rs` unit tests —
// M5 made `owasp_params` crate-private.)

// ---------------------------------------------------------------------------
// HKDF-SHA256 — RFC 5869 Appendix A.1 Test Case 1 (official vector).
// ---------------------------------------------------------------------------

/// SR-F5 / SR-C3: RFC 5869 Appendix A.1 Test Case 1 (SHA-256) reproduces the
/// exact PRK and 42-byte OKM through the `hkdf` crate — locking the HKDF-SHA256
/// primitive against the official IETF known answer.
#[test]
fn test_sr_f5_rfc5869_hkdf_sha256_official_vector() {
    let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let expected_prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    let expected_okm =
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    let (prk, hk) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
    assert_eq!(
        prk.as_slice(),
        expected_prk.as_slice(),
        "RFC 5869 A.1: PRK mismatch"
    );
    let mut okm = vec![0u8; expected_okm.len()];
    hk.expand(&info, &mut okm).unwrap();
    assert_eq!(okm, expected_okm, "RFC 5869 A.1: OKM mismatch");
}

/// SR-F5 / SR-C3: the crate's sub-key expanders use HKDF-SHA256 with `salt=None`
/// and the pinned `info` labels — cross-checked byte-for-byte against an in-test
/// HKDF reference — and the two sub-keys are domain-separated (distinct, neither
/// equal to the raw master).
#[test]
fn test_sr_f5_hkdf_subkey_labels_and_domain_separation() {
    let master = [0x5Au8; KEY_LEN];

    // In-test reference: HKDF-SHA256, salt=None, the pinned info labels.
    let reference = |info: &[u8]| -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(None, &master);
        let mut out = vec![0u8; KEY_LEN];
        hk.expand(info, &mut out).unwrap();
        out
    };
    let aead_ref = reference(b"cryptovault:v1:aead");
    let seed_ref = reference(b"cryptovault:v1:interleaver");

    let aead = expand_aead_key(&master).unwrap();
    let seed = expand_interleaver_seed(&master).unwrap();
    assert_eq!(
        &*aead,
        aead_ref.as_slice(),
        "AEAD key uses info=cryptovault:v1:aead"
    );
    assert_eq!(
        &*seed,
        seed_ref.as_slice(),
        "interleaver seed uses info=cryptovault:v1:interleaver"
    );
    assert_ne!(
        &*aead, &*seed,
        "domain separation: aead key != interleaver seed"
    );
    assert_ne!(
        &*aead,
        master.as_slice(),
        "sub-key never equals the raw master"
    );
}

// ---------------------------------------------------------------------------
// Reed-Solomon RS(255,223) — independent `reedsolo` parity reference.
// ---------------------------------------------------------------------------

/// The 32 parity bytes the third-party `reedsolo` library appends to the block
/// `0, 1, …, 222` (`fcr=112, prim=0x187, gen=2`, the CCSDS convention). An
/// implementation unrelated to the `reedsolomon` crate under test.
const RS255_REF_PARITY: [u8; RS_PARITY] = [
    158, 231, 74, 155, 39, 244, 58, 206, 26, 141, 128, 252, 255, 161, 132, 86, 196, 126, 234, 128,
    90, 90, 160, 125, 98, 145, 75, 186, 191, 203, 254, 81,
];

/// SR-F5 / SR-F1: `ReedSolomonCodec` encodes the canonical block `0..=222` to a
/// systematic 255-byte codeword whose 32 parity bytes match the independent
/// `reedsolo` reference exactly, and a known 16-byte error pattern (at capacity)
/// is corrected back to the original.
#[test]
fn test_sr_f5_rs255_codeword_parity_and_known_error_correction() {
    let rs = ReedSolomonCodec;
    let data: Vec<u8> = (0u8..=222).collect();
    let encoded = rs.encode(&data);
    assert_eq!(encoded.len(), RS_BLOCK, "one 223-byte block → one codeword");
    assert_eq!(
        &encoded[..RS_DATA],
        data.as_slice(),
        "systematic prefix intact"
    );
    assert_eq!(
        &encoded[RS_DATA..],
        RS255_REF_PARITY,
        "parity must match the independent reedsolo reference"
    );

    // Known error pattern: flip byte at positions 0,3,6,…,45 (16 errors = t).
    let mut corrupted = encoded.clone();
    for i in 0..(RS_PARITY / 2) {
        corrupted[i * 3] ^= 0x5A;
    }
    assert_eq!(
        rs.decode(&corrupted, data.len()).unwrap(),
        data,
        "16 known errors (at capacity) are corrected exactly"
    );
}

/// SR-F5 / SR-F1 (L11): two additional independent multi-symbol error patterns
/// through the crate `ReedSolomonCodec` recover exactly within capacity, and a
/// 17-symbol pattern surfaces a typed `ErrorCorrection` error (fail-loud). The
/// data blocks and error positions are chosen/documented here, independent of the
/// parity reference above.
#[test]
fn test_sr_f5_rs255_additional_error_patterns_recover_and_fail_loud() {
    use cryptovault::error::CryptoError;

    let rs = ReedSolomonCodec;

    // Pattern A — `b[i] = (7*i + 3) mod 256`, 12 scattered errors (< t).
    let data_a: Vec<u8> = (0..RS_DATA).map(|i| (7 * i + 3) as u8).collect();
    let enc_a = rs.encode(&data_a);
    const POS_A: [usize; 12] = [0, 11, 22, 55, 90, 111, 150, 177, 200, 210, 221, 254];
    let mut corrupt_a = enc_a.clone();
    for &p in &POS_A {
        corrupt_a[p] ^= 0xA5;
    }
    assert_eq!(
        rs.decode(&corrupt_a, data_a.len()).unwrap(),
        data_a,
        "pattern A: 12 known scattered errors corrected exactly"
    );

    // Pattern B — constant `0xC3`, exactly 16 errors (= t): 8 contiguous + 8 spread.
    let data_b: Vec<u8> = vec![0xC3u8; RS_DATA];
    let enc_b = rs.encode(&data_b);
    const POS_B: [usize; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 60, 80, 120, 160, 200, 230, 240, 250];
    let mut corrupt_b = enc_b.clone();
    for &p in &POS_B {
        corrupt_b[p] ^= 0xFF;
    }
    assert_eq!(
        rs.decode(&corrupt_b, data_b.len()).unwrap(),
        data_b,
        "pattern B: 16 known errors (at capacity) corrected exactly"
    );

    // 17 distinct errors exceed `t` → typed ErrorCorrection, never mis-corrected.
    const POS_C: [usize; 17] = [
        0, 15, 30, 45, 60, 75, 90, 105, 120, 135, 150, 165, 180, 195, 210, 225, 240,
    ];
    let mut corrupt_c = enc_b.clone();
    for &p in &POS_C {
        corrupt_c[p] ^= 0x3C;
    }
    assert!(
        matches!(
            rs.decode(&corrupt_c, data_b.len()),
            Err(CryptoError::ErrorCorrection(_))
        ),
        "17 errors must fail loud, never silently mis-correct"
    );
}

// ---------------------------------------------------------------------------
// Viterbi K=7 R=1/2 — CCSDS impulse reference + known blob body.
// ---------------------------------------------------------------------------

/// SR-F5 / SR-F3 (L11): two distinct known RS-streams round-trip through the
/// crate `ViterbiCodec` with a within-capacity coded-bit error injected —
/// exercising different trellis-state trajectories beyond the impulse vector.
#[test]
fn test_sr_f5_viterbi_distinct_streams_roundtrip_within_capacity() {
    let v = ViterbiCodec;
    let streams: [Vec<u8>; 2] = [
        (0..RS_BLOCK as u32).map(|i| (13 * i + 7) as u8).collect(),
        vec![0xF0u8; RS_BLOCK],
    ];
    for stream in &streams {
        let mut body = v.encode(stream);
        assert_eq!(body.len(), 2 * RS_BLOCK + 2, "coded body is 2L + 2 bytes");
        let mid = body.len() / 2;
        body[mid] ^= 0x01; // one coded-bit error, within capacity
        assert_eq!(
            v.decode(&body).unwrap(),
            *stream,
            "distinct RS-stream recovered exactly through a single-bit error"
        );
    }
}

/// SR-F5 / SR-F3 / P0-3: the inner Viterbi codec reproduces the independent
/// CCSDS 131.0-B impulse response `[0xBA, 0x48]` (via the underlying encoder),
/// `ViterbiCodec` encodes a known RS-stream to the pinned `2L + 2` body length,
/// and a single injected coded-bit error is corrected back to the original.
#[test]
fn test_sr_f5_viterbi_ccsds_impulse_and_known_body_recovery() {
    use viterbi::{CodeParams, ViterbiEncoder};

    // Independent CCSDS impulse: one info bit `1` + 6-bit zero tail, MSB-first.
    let enc = ViterbiEncoder::new(CodeParams::ccsds_r1_2()).expect("CCSDS params valid");
    let impulse = enc.encode_bits(&[0x80], 1).expect("single-bit encode");
    assert_eq!(
        impulse.bytes.as_slice(),
        [0xBA, 0x48],
        "codec must reproduce the CCSDS 131.0-B impulse response"
    );
    assert_eq!(impulse.nbits, 14, "7 trellis stages × 2 output bits");

    // Known RS-stream → known blob-body length (2L + 2), then error-injection
    // recovery through the byte-level `ViterbiCodec`.
    let v = ViterbiCodec;
    let stream: Vec<u8> = (0..RS_BLOCK as u32).map(|i| i as u8).collect();
    let body = v.encode(&stream);
    assert_eq!(
        body.len(),
        2 * RS_BLOCK + 2,
        "coded body is exactly 2L + 2 bytes"
    );

    let mut corrupted = body.clone();
    corrupted[body.len() / 2] ^= 0x01; // one coded-bit error, within capacity
    assert_eq!(
        v.decode(&corrupted).unwrap(),
        stream,
        "a single coded-bit error is corrected, RS-stream recovered exactly"
    );
}

// ---------------------------------------------------------------------------
// Interleavers — block permutation anchors + CSPRNG golden vector.
// ---------------------------------------------------------------------------

/// SR-F5 / P0-1: the deterministic block interleaver (`depth=5`) produces the
/// hand-derived column-major output for a fixed input (`in[i] = i as u8`),
/// handles the final partial window as identity, and round-trips — locking the
/// public/fixed block permutation.
#[test]
fn test_sr_f5_block_interleaver_known_permutation_and_partial_window() {
    let depth = 5usize;
    let il = BlockInterleaver::new(depth).unwrap();
    let len = depth * RS_BLOCK + 100; // one full window + a 100-byte tail
    let stream: Vec<u8> = (0..len).map(|i| i as u8).collect();
    let out = il.interleave(&stream);

    // Column-major read: out[k] = in[row*255 + col], k = col*depth + row.
    // Anchors hand-derived from that mapping (values are index mod 256).
    let anchors: [(usize, u8); 7] = [
        (0, 0),   // col0,row0 → idx0
        (1, 255), // col0,row1 → idx255
        (2, 254), // col0,row2 → idx510
        (3, 253), // col0,row3 → idx765
        (4, 252), // col0,row4 → idx1020
        (5, 1),   // col1,row0 → idx1
        (6, 0),   // col1,row1 → idx256
    ];
    for (k, expected) in anchors {
        assert_eq!(out[k], expected, "block permutation anchor at k={k}");
    }

    // Final partial window (100 bytes < RS_BLOCK): only row 0 populated →
    // column-major read is the identity.
    let win = depth * RS_BLOCK;
    assert_eq!(&out[win..], &stream[win..], "partial window is identity");

    // Round-trip closes the KAT.
    assert_eq!(
        il.deinterleave(&out),
        stream,
        "block interleaver round-trips"
    );
}

/// SR-F5 / P0-1: the optional CSPRNG interleaver layer produces a locked golden
/// output for a fixed seed + input (pinning the
/// ChaCha20 → rejection-sample → Fisher-Yates derivation) and round-trips,
/// including a final partial window.
#[test]
fn test_sr_f5_csprng_layer_golden_vector_and_partial_window() {
    // Single-codeword window keeps the golden vector short while exercising the
    // full derivation.
    let layer = CsprngLayer::new(&[0x42u8; KEY_LEN]).unwrap();
    let window_len = RS_BLOCK;
    let stream: Vec<u8> = (0..RS_BLOCK as u32).map(|i| i as u8).collect();
    let out = layer.interleave(&stream, window_len);
    const GOLDEN_HEAD: [u8; 16] = [
        249, 67, 112, 93, 186, 69, 114, 89, 224, 248, 92, 219, 140, 64, 91, 56,
    ];
    assert_eq!(
        &out[..16],
        &GOLDEN_HEAD,
        "CSPRNG derivation is format-locked"
    );
    assert_eq!(
        layer.deinterleave(&out, window_len),
        stream,
        "CSPRNG round-trips"
    );

    // A larger window with a trailing partial window still round-trips.
    let window_len = 5 * RS_BLOCK;
    let stream: Vec<u8> = (0..(window_len as u32 + 137)).map(|i| i as u8).collect();
    let out = layer.interleave(&stream, window_len);
    assert_eq!(
        layer.deinterleave(&out, window_len),
        stream,
        "CSPRNG round-trips across a partial final window"
    );
}
