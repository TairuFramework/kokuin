//! Base58btc, multibase and SHA-256 multihash, as `@scure/base` `base58` and
//! `packages/token/src/multibase.ts`.

use sha2::{Digest, Sha256};

use crate::TokenError;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// `@scure/base` refuses to encode more bytes than this (base58 is O(n^2)).
const MAX_ENCODE_BYTES: usize = 2048;
/// `@scure/base` refuses to decode more characters than this.
const MAX_DECODE_CHARS: usize = 4096;

const MULTIBASE_BASE58BTC: char = 'z';
const MULTIHASH_SHA256_CODE: u8 = 0x12;
const MULTIHASH_SHA256_LENGTH: u8 = 0x20;

/// The length of a string in UTF-16 code units, as JavaScript's `String#length`.
pub(crate) fn js_length(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Encode bytes as base58btc. Leading zero bytes become leading `1` digits.
pub fn base58_encode(bytes: &[u8]) -> Result<String, TokenError> {
    if bytes.len() > MAX_ENCODE_BYTES {
        return Err(TokenError::invalid("invalid length"));
    }
    let zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
    // Little-endian base58 digits of the value after the leading zeros.
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in &bytes[zeros..] {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(
        digits
            .iter()
            .rev()
            .map(|&digit| char::from(ALPHABET[usize::from(digit)])),
    );
    Ok(out)
}

/// Decode base58btc. Leading `1` digits become leading zero bytes.
pub fn base58_decode(text: &str) -> Result<Vec<u8>, TokenError> {
    if js_length(text) > MAX_DECODE_CHARS {
        return Err(TokenError::invalid("invalid length"));
    }
    let mut values = Vec::with_capacity(text.len());
    for letter in text.chars() {
        let value = u8::try_from(letter)
            .ok()
            .and_then(|byte| ALPHABET.iter().position(|&candidate| candidate == byte));
        match value {
            Some(value) => values.push(value as u32),
            None => {
                let alphabet = std::str::from_utf8(ALPHABET).unwrap_or_default();
                return Err(TokenError::invalid(format!(
                    "Unknown letter \"{letter}\". Allowed: {alphabet}"
                )));
            }
        }
    }
    let zeros = values.iter().take_while(|&&value| value == 0).count();
    // Little-endian bytes of the value after the leading zeros.
    let mut bytes: Vec<u8> = Vec::with_capacity(values.len());
    for &value in &values[zeros..] {
        let mut carry = value;
        for byte in bytes.iter_mut() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Ok(out)
}

/// Encode bytes as a base58btc multibase string (`z` prefix).
pub fn encode(bytes: &[u8]) -> Result<String, TokenError> {
    Ok(format!("{MULTIBASE_BASE58BTC}{}", base58_encode(bytes)?))
}

/// Decode a multibase string. Only base58btc (`z`) is supported.
pub fn decode(value: &str) -> Result<Vec<u8>, TokenError> {
    let Some(prefix) = value.chars().next() else {
        return Err(TokenError::invalid(
            "Invalid multibase encoding: empty string",
        ));
    };
    if prefix != MULTIBASE_BASE58BTC {
        return Err(TokenError::invalid(format!(
            "Unsupported multibase prefix: {prefix}"
        )));
    }
    base58_decode(&value[1..])
}

/// The SHA-256 multihash of `bytes`: `0x12 0x20` followed by the digest.
pub fn multihash_sha256(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![MULTIHASH_SHA256_CODE, MULTIHASH_SHA256_LENGTH];
    out.extend_from_slice(&Sha256::digest(bytes));
    out
}

/// Whether `multihash` is the SHA-256 multihash of `bytes`.
pub fn verify_multihash(multihash: &[u8], bytes: &[u8]) -> bool {
    multihash.len() == 2 + usize::from(MULTIHASH_SHA256_LENGTH)
        && multihash[0] == MULTIHASH_SHA256_CODE
        && multihash[1] == MULTIHASH_SHA256_LENGTH
        && multihash[2..] == Sha256::digest(bytes)[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_round_trips_leading_zeros() {
        for bytes in [
            vec![],
            vec![0],
            vec![0, 0, 0],
            vec![0, 0, 1, 2, 255],
            vec![255; 40],
        ] {
            let text = base58_encode(&bytes).unwrap();
            assert_eq!(base58_decode(&text).unwrap(), bytes);
        }
        assert_eq!(base58_encode(&[0, 0, 0]).unwrap(), "111");
        assert_eq!(base58_encode(b"hello world").unwrap(), "StV1DL6CwTryKyV");
    }

    #[test]
    fn base58_limits_and_letters() {
        assert_eq!(
            base58_encode(&[1; 2049]),
            Err(TokenError::invalid("invalid length"))
        );
        assert!(base58_encode(&[1; 2048]).is_ok());
        assert_eq!(
            base58_decode(&"2".repeat(4097)),
            Err(TokenError::invalid("invalid length"))
        );
        assert!(
            base58_decode("0")
                .unwrap_err()
                .to_string()
                .starts_with("Unknown letter \"0\". Allowed: 123")
        );
    }

    #[test]
    fn multibase_prefixes() {
        assert_eq!(
            decode(""),
            Err(TokenError::invalid(
                "Invalid multibase encoding: empty string"
            ))
        );
        assert_eq!(
            decode("m00"),
            Err(TokenError::invalid("Unsupported multibase prefix: m"))
        );
        assert_eq!(decode("z").unwrap(), Vec::<u8>::new());
    }
}
