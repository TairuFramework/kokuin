//! Multicodec-tagged keys, as `packages/controller/src/keys.ts`.

use kokuin_token::multibase;

/// A key algorithm a controller log publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// Ed25519, for signing.
    EdDSA,
    /// X25519, for key agreement.
    X25519,
}

impl KeyAlgorithm {
    /// The TS name: `EdDSA` or `X25519`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EdDSA => "EdDSA",
            Self::X25519 => "X25519",
        }
    }

    fn codec(self) -> [u8; 2] {
        match self {
            Self::EdDSA => [0xed, 0x01],
            Self::X25519 => [0xec, 0x01],
        }
    }
}

const KEY_LENGTH: usize = 32;

/// Tag and multibase-encode a public key (`encodeKey`).
pub fn encode_key(alg: KeyAlgorithm, public_key: &[u8]) -> String {
    let mut bytes = alg.codec().to_vec();
    bytes.extend_from_slice(public_key);
    multibase::encode(&bytes).unwrap_or_default()
}

/// Decode a tagged key; any malformed, unknown-codec or wrong-length value yields `None`
/// (`tryDecodeKey`).
pub fn try_decode_key(value: &str) -> Option<(KeyAlgorithm, Vec<u8>)> {
    let bytes = multibase::decode(value).ok()?;
    for alg in [KeyAlgorithm::EdDSA, KeyAlgorithm::X25519] {
        let codec = alg.codec();
        if bytes.len() > codec.len() && bytes[..2] == codec {
            let public_key = &bytes[codec.len()..];
            return (public_key.len() == KEY_LENGTH).then(|| (alg, public_key.to_vec()));
        }
    }
    None
}

/// [`try_decode_key`], failing with the TS message (`decodeKey`).
pub(crate) fn decode_key(value: &str) -> Result<(KeyAlgorithm, Vec<u8>), String> {
    try_decode_key(value).ok_or_else(|| format!("Unrecognised key encoding: {value}"))
}
