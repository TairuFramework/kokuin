use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::CryptoError;

pub fn sign_ed25519(seed: &[u8], message: &[u8]) -> Result<[u8; 64], CryptoError> {
    let seed: &[u8; 32] = seed.try_into().map_err(|_| CryptoError::InvalidSeed)?;
    // SigningKey zeroises its internal seed on drop. The borrowed caller buffer is not retained.
    let key = SigningKey::from_bytes(seed);
    Ok(key.sign(message).to_bytes())
}

fn strict_point(bytes: &[u8; 32]) -> bool {
    let Some(point) = CompressedEdwardsY(*bytes).decompress() else {
        return false;
    };
    point.compress().as_bytes() == bytes && !point.is_small_order() && point.is_torsion_free()
}

pub fn verify(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    let Ok(key_bytes) = <&[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(signature) else {
        return false;
    };
    let signature_bytes = signature.to_bytes();
    let r: &[u8; 32] = signature_bytes[..32]
        .try_into()
        .expect("fixed signature length");
    if !strict_point(key_bytes) || !strict_point(r) {
        return false;
    }
    let Ok(key) = VerifyingKey::from_bytes(key_bytes) else {
        return false;
    };
    key.verify_strict(message, &signature).is_ok()
}
