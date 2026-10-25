#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoSlice {
    pub data: *const u8,
    pub len: usize,
}

#[repr(C)]
pub struct CryptoBuffer {
    pub data: *mut u8,
    pub len: usize,
}

#[unsafe(no_mangle)]
pub extern "C" fn kokuin_crypto_abi_version() -> u32 {
    1
}

/// # Safety
/// Input pointers must reference readable allocations of their declared lengths.
/// `output` must reference an aligned, writable CryptoBuffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kokuin_crypto_execute(
    operation: u32,
    algorithm: u32,
    key: CryptoSlice,
    message: CryptoSlice,
    signature: CryptoSlice,
    output_len: u32,
    output: *mut CryptoBuffer,
) -> i32 {
    if output.is_null() {
        return 1;
    }
    unsafe {
        *output = CryptoBuffer {
            data: std::ptr::null_mut(),
            len: 0,
        }
    };
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<Vec<u8>, i32> {
        let key = unsafe { checked_slice(key)? };
        let message = unsafe { checked_slice(message)? };
        let signature = unsafe { checked_slice(signature)? };
        match operation {
            1 if algorithm == 1 => sign_ed25519(key, message)
                .map(|value| value.to_vec())
                .map_err(|_| 2),
            2 => {
                let algorithm = match algorithm {
                    1 => Algorithm::Ed25519,
                    2 => Algorithm::Es256,
                    _ => return Err(1),
                };
                Ok(vec![u8::from(verify(algorithm, signature, message, key))])
            }
            3 => hash_blake3(message, output_len as usize).map_err(|_| 3),
            _ => Err(1),
        }
    }));
    match result {
        Ok(Ok(bytes)) => {
            let mut bytes = bytes.into_boxed_slice();
            unsafe {
                *output = CryptoBuffer {
                    data: bytes.as_mut_ptr(),
                    len: bytes.len(),
                }
            };
            std::mem::forget(bytes);
            0
        }
        Ok(Err(status)) => status,
        Err(_) => 4,
    }
}

unsafe fn checked_slice<'a>(input: CryptoSlice) -> Result<&'a [u8], i32> {
    if input.len == 0 {
        return Ok(&[]);
    }
    if input.data.is_null() || input.len > isize::MAX as usize {
        return Err(1);
    }
    Ok(unsafe { std::slice::from_raw_parts(input.data, input.len) })
}

/// # Safety
/// Buffer must come from a successful execute call and must be freed exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kokuin_crypto_free(buffer: CryptoBuffer) {
    if !buffer.data.is_null() {
        let slice = std::ptr::slice_from_raw_parts_mut(buffer.data, buffer.len);
        drop(unsafe { Box::from_raw(slice) });
    }
}
use std::panic::{AssertUnwindSafe, catch_unwind};

use kokuin_crypto::{Algorithm, hash_blake3, sign_ed25519, verify};
