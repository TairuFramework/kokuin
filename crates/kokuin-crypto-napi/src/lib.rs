//! Node-API bindings over `kokuin-crypto` for `@kokuin/crypto-napi`.
//!
//! The JavaScript provider validates every argument before calling in, so these functions only
//! report what the core reports. Single calls run on the calling thread. Batch calls copy their
//! inputs on the calling thread, which preserves the contract's snapshot semantics, then compute
//! on the libuv thread pool and resolve a Promise.

use kokuin_crypto::{Algorithm, hash_blake3, sign_ed25519, verify};
use napi::bindgen_prelude::{AsyncTask, Uint8Array};
use napi::{Env, Error, Result, Task};
use napi_derive::napi;
use zeroize::Zeroizing;

/// Bumped whenever an export changes shape, so the provider can refuse a stale binary.
#[napi]
pub const ABI_VERSION: u32 = 1;

fn algorithm(es256: bool) -> Algorithm {
    if es256 {
        Algorithm::Es256
    } else {
        Algorithm::Ed25519
    }
}

#[napi]
pub fn sign(seed: &[u8], message: &[u8]) -> Result<Uint8Array> {
    sign_ed25519(seed, message)
        .map(|signature| Uint8Array::from(signature.to_vec()))
        .map_err(|_| Error::from_reason("invalid Ed25519 seed"))
}

#[napi(js_name = "verify")]
pub fn verify_one(es256: bool, signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    verify(algorithm(es256), signature, message, public_key)
}

#[napi]
pub fn blake3(input: &[u8], length: u32) -> Result<Uint8Array> {
    hash_blake3(input, length as usize)
        .map(Uint8Array::from)
        .map_err(|_| Error::from_reason("invalid blake3 output length"))
}

/// Seed copies are `Zeroizing`, so they are wiped when the task drops after resolving.
pub struct SignBatch {
    items: Vec<(Zeroizing<Vec<u8>>, Vec<u8>)>,
}

impl Task for SignBatch {
    type Output = Vec<Vec<u8>>;
    type JsValue = Vec<Uint8Array>;

    fn compute(&mut self) -> Result<Self::Output> {
        self.items
            .iter()
            .map(|(seed, message)| {
                sign_ed25519(seed, message)
                    .map(|signature| signature.to_vec())
                    .map_err(|_| Error::from_reason("invalid Ed25519 seed"))
            })
            .collect()
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into_iter().map(Uint8Array::from).collect())
    }
}

#[napi]
pub fn sign_batch(
    seeds: Vec<Uint8Array>,
    messages: Vec<Uint8Array>,
) -> Result<AsyncTask<SignBatch>> {
    if seeds.len() != messages.len() {
        return Err(Error::from_reason("seed and message counts differ"));
    }
    let items = seeds
        .iter()
        .zip(messages.iter())
        .map(|(seed, message)| (Zeroizing::new(seed.to_vec()), message.to_vec()))
        .collect();
    Ok(AsyncTask::new(SignBatch { items }))
}

struct VerifyItem {
    es256: bool,
    signature: Vec<u8>,
    message: Vec<u8>,
    public_key: Vec<u8>,
}

pub struct VerifyBatch {
    items: Vec<VerifyItem>,
}

impl Task for VerifyBatch {
    type Output = Vec<bool>;
    type JsValue = Vec<bool>;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(self
            .items
            .iter()
            .map(|item| {
                verify(
                    algorithm(item.es256),
                    &item.signature,
                    &item.message,
                    &item.public_key,
                )
            })
            .collect())
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn verify_batch(
    es256: Vec<bool>,
    signatures: Vec<Uint8Array>,
    messages: Vec<Uint8Array>,
    public_keys: Vec<Uint8Array>,
) -> Result<AsyncTask<VerifyBatch>> {
    let count = es256.len();
    if signatures.len() != count || messages.len() != count || public_keys.len() != count {
        return Err(Error::from_reason("verification field counts differ"));
    }
    let items = (0..count)
        .map(|index| VerifyItem {
            es256: es256[index],
            signature: signatures[index].to_vec(),
            message: messages[index].to_vec(),
            public_key: public_keys[index].to_vec(),
        })
        .collect();
    Ok(AsyncTask::new(VerifyBatch { items }))
}

pub struct Blake3Batch {
    inputs: Vec<Vec<u8>>,
    length: usize,
}

impl Task for Blake3Batch {
    type Output = Vec<Vec<u8>>;
    type JsValue = Vec<Uint8Array>;

    fn compute(&mut self) -> Result<Self::Output> {
        self.inputs
            .iter()
            .map(|input| {
                hash_blake3(input, self.length)
                    .map_err(|_| Error::from_reason("invalid blake3 output length"))
            })
            .collect()
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into_iter().map(Uint8Array::from).collect())
    }
}

#[napi]
pub fn blake3_batch(inputs: Vec<Uint8Array>, length: u32) -> AsyncTask<Blake3Batch> {
    AsyncTask::new(Blake3Batch {
        inputs: inputs.iter().map(|input| input.to_vec()).collect(),
        length: length as usize,
    })
}
