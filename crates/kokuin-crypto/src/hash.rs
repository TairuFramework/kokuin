use crate::CryptoError;

pub fn hash_blake3(input: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    if !(1..=65536).contains(&output_len) {
        return Err(CryptoError::InvalidOutputLength);
    }
    let mut output = vec![0; output_len];
    blake3::Hasher::new()
        .update(input)
        .finalize_xof()
        .fill(&mut output);
    Ok(output)
}
