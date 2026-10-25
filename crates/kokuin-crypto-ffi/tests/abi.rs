use kokuin_crypto_ffi::{CryptoBuffer, CryptoSlice, kokuin_crypto_execute, kokuin_crypto_free};

fn slice(bytes: &[u8]) -> CryptoSlice {
    CryptoSlice {
        data: bytes.as_ptr(),
        len: bytes.len(),
    }
}
fn empty() -> CryptoSlice {
    CryptoSlice {
        data: std::ptr::null(),
        len: 0,
    }
}

#[test]
fn hashes_empty_null_slice_and_releases_owned_output() {
    let mut output = CryptoBuffer {
        data: std::ptr::null_mut(),
        len: 0,
    };
    let status = unsafe { kokuin_crypto_execute(3, 0, empty(), empty(), empty(), 32, &mut output) };
    assert_eq!(status, 0);
    let bytes = unsafe { std::slice::from_raw_parts(output.data, output.len) };
    assert_eq!(&bytes[..4], &[0xaf, 0x13, 0x49, 0xb9]);
    unsafe { kokuin_crypto_free(output) };
}

#[test]
fn rejects_bad_descriptors_algorithms_and_output_lengths() {
    let mut output = CryptoBuffer {
        data: std::ptr::null_mut(),
        len: 0,
    };
    let invalid = CryptoSlice {
        data: std::ptr::null(),
        len: 1,
    };
    for (op, alg, input, len) in [
        (3, 0, invalid, 32),
        (2, 99, empty(), 0),
        (3, 0, empty(), 0),
        (99, 0, empty(), 32),
    ] {
        assert_ne!(
            unsafe { kokuin_crypto_execute(op, alg, empty(), input, empty(), len, &mut output) },
            0
        );
        assert!(output.data.is_null());
        assert_eq!(output.len, 0);
    }
}

#[test]
fn malformed_signatures_are_false_rather_than_request_errors() {
    let mut output = CryptoBuffer {
        data: std::ptr::null_mut(),
        len: 0,
    };
    assert_eq!(
        unsafe { kokuin_crypto_execute(2, 1, slice(&[0; 32]), empty(), empty(), 0, &mut output) },
        0
    );
    assert_eq!(unsafe { *output.data }, 0);
    unsafe { kokuin_crypto_free(output) };
}
