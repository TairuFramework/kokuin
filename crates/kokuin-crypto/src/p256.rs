use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

pub fn verify(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    if !matches!(public_key, [2 | 3, ..] if public_key.len() == 33)
        && !matches!(public_key, [4, ..] if public_key.len() == 65)
    {
        return false;
    }
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    // Reject malleable input instead of accepting a normalised replacement.
    if signature != signature.normalize_s() {
        return false;
    }
    let Ok(key) = VerifyingKey::from_sec1_bytes(public_key) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}
