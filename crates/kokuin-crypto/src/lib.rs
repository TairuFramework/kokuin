#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    Ed25519,
    Es256,
}

#[derive(Debug, PartialEq)]
pub enum CryptoError {
    InvalidSeed,
    InvalidOutputLength,
}

pub use ed25519::sign_ed25519;
pub use hash::hash_blake3;

pub fn verify(algorithm: Algorithm, signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    match algorithm {
        Algorithm::Ed25519 => ed25519::verify(signature, message, public_key),
        Algorithm::Es256 => p256::verify(signature, message, public_key),
    }
}
mod ed25519;
mod hash;
mod p256;
