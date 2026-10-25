use kokuin_crypto::{Algorithm, CryptoError, hash_blake3, sign_ed25519, verify};

const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const SIGNATURE: &str = concat!(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
);

fn bytes(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap()
}

#[test]
fn signs_rfc8032_empty_message() {
    assert_eq!(
        sign_ed25519(&bytes(SEED), &[]).unwrap().as_slice(),
        bytes(SIGNATURE)
    );
}

#[test]
fn verifies_rfc8032_and_rejects_mutated_message() {
    assert!(verify(
        Algorithm::Ed25519,
        &bytes(SIGNATURE),
        &[],
        &bytes(KEY)
    ));
    assert!(!verify(
        Algorithm::Ed25519,
        &bytes(SIGNATURE),
        &[1],
        &bytes(KEY)
    ));
}

#[test]
fn rejects_identity_points_and_invalid_lengths() {
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut forgery = [0; 64];
    forgery[..32].copy_from_slice(&identity);
    assert!(!verify(Algorithm::Ed25519, &forgery, &[], &identity));
    assert!(!verify(Algorithm::Ed25519, &[], &[], &bytes(KEY)));
    assert_eq!(sign_ed25519(&[0; 31], &[]), Err(CryptoError::InvalidSeed));
}

#[test]
fn verifies_compact_low_s_p256_without_double_hashing() {
    let key = bytes("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    let message = b"kokuin crypto spike";
    let low = bytes(concat!(
        "d8993d42f5ff5aaf214a10145e5f9ad8bd572acd022d87bd4d8bf989319619e1",
        "205bca699914f7f3319fd760301ff494ef95a793ed79c534bab8fbdfcdbcbd58"
    ));
    let high = bytes(concat!(
        "d8993d42f5ff5aaf214a10145e5f9ad8bd572acd022d87bd4d8bf989319619e1",
        "dfa4359566eb080dce60289fcfe00b6acd515319b99dd9503900cee32ea667f9"
    ));
    assert!(verify(Algorithm::Es256, &low, message, &key));
    assert!(!verify(Algorithm::Es256, &high, message, &key));
    assert!(!verify(Algorithm::Es256, &low, b"mutated", &key));
    assert!(!verify(Algorithm::Es256, &[0; 64], message, &key));
    assert!(!verify(Algorithm::Es256, &low, message, &[4; 65]));
}

#[test]
fn matches_official_blake3_empty_outputs() {
    // BLAKE3-team/BLAKE3 test_vectors/test_vectors.json, input_len=0.
    let expected = bytes(concat!(
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a"
    ));
    for length in [16, 32, 64] {
        assert_eq!(hash_blake3(&[], length).unwrap(), expected[..length]);
    }
    assert_eq!(hash_blake3(&[], 0), Err(CryptoError::InvalidOutputLength));
    assert_eq!(
        hash_blake3(&[], 65537),
        Err(CryptoError::InvalidOutputLength)
    );
}
