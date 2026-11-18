//! `did:key` encoding, as `getDID`, `getSignatureInfo` and `getAlgorithmAndPublicKey` in
//! `packages/token/src/did.ts`.

use crate::multibase::{base58_decode, base58_encode, js_length};
use crate::{SignatureAlgorithm, TokenError};

const PREFIX: &str = "did:key:z";
/// ES256, the largest supported key, encodes to 48 characters. Bound before the O(n^2) decode.
pub(crate) const MAX_DID_KEY_ENCODED: usize = 64;

/// The multicodec prefix `did:key` uses for an algorithm's public key.
pub fn codec(algorithm: SignatureAlgorithm) -> &'static [u8] {
    match algorithm {
        SignatureAlgorithm::ES256 => &[0x80, 0x24],
        SignatureAlgorithm::EdDSA => &[0xed, 0x01],
    }
}

fn expected_key_size(algorithm: SignatureAlgorithm) -> usize {
    match algorithm {
        SignatureAlgorithm::EdDSA => 32,
        SignatureAlgorithm::ES256 => 33,
    }
}

/// Split multicodec-prefixed key bytes into their algorithm and raw public key, or `None` when the
/// prefix names no supported algorithm. Checks ES256 first, as `Object.entries(CODECS)` does.
pub fn algorithm_and_public_key(bytes: &[u8]) -> Option<(SignatureAlgorithm, Vec<u8>)> {
    [SignatureAlgorithm::ES256, SignatureAlgorithm::EdDSA]
        .into_iter()
        .find_map(|algorithm| {
            bytes
                .strip_prefix(codec(algorithm))
                .map(|key| (algorithm, key.to_vec()))
        })
}

/// Encode a public key as a `did:key` identifier (`getDID`).
///
/// A key of any length encodes, as in TS; only a key over 2046 bytes, which no algorithm has,
/// exceeds the base58 limit, and it yields the prefix alone.
pub fn encode(algorithm: SignatureAlgorithm, public_key: &[u8]) -> String {
    let mut bytes = codec(algorithm).to_vec();
    bytes.extend_from_slice(public_key);
    format!("{PREFIX}{}", base58_encode(&bytes).unwrap_or_default())
}

/// The algorithm and raw public key a `did:key` carries (`getSignatureInfo`).
pub fn decode(did: &str) -> Result<(SignatureAlgorithm, Vec<u8>), TokenError> {
    let Some(encoded) = did.strip_prefix(PREFIX) else {
        return Err(TokenError::invalid("Invalid DID format"));
    };
    if js_length(encoded) > MAX_DID_KEY_ENCODED {
        return Err(TokenError::invalid("Invalid DID format: key too large"));
    }
    let bytes = base58_decode(encoded)?;
    let Some((algorithm, public_key)) = algorithm_and_public_key(&bytes) else {
        return Err(TokenError::invalid("Unsupported DID signature codec"));
    };
    if public_key.len() != expected_key_size(algorithm) {
        return Err(TokenError::invalid("Invalid public key size"));
    }
    Ok((algorithm, public_key))
}

pub(crate) fn has_prefix(did: &str) -> bool {
    did.starts_with(PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_identifiers() {
        let error = |did: &str| decode(did).unwrap_err().to_string();
        assert_eq!(error("did:key:abc"), "Invalid DID format");
        assert_eq!(
            error(&format!("did:key:z{}", "2".repeat(65))),
            "Invalid DID format: key too large"
        );
        assert_eq!(
            error(&encode(SignatureAlgorithm::EdDSA, &[1; 31])),
            "Invalid public key size"
        );
        let unknown = format!("did:key:z{}", base58_encode(&[0xec, 0x01, 1, 2]).unwrap());
        assert_eq!(error(&unknown), "Unsupported DID signature codec");
    }
}
