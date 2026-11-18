//! A content-addressed store of did:peer:4 documents, keyed by short form, as
//! `packages/token/src/cache.ts`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use serde_json::Value;

use crate::TokenError;
use crate::peer4::{self, DEFAULT_MAX_DOC_SIZE};

/// A did:peer:4 document cache (TS `DIDCache`). Verification reads it before the resolver and
/// writes a document to it only after the signature verifies.
pub trait DIDCache {
    /// The document cached for a short form.
    fn get(&self, short_form: &str) -> Option<Value>;

    /// Store a document. Implementations must refuse a document that does not hash to
    /// `short_form`.
    fn set(&self, short_form: &str, doc: &Value) -> Result<(), TokenError>;
}

/// The default bound on [`InMemoryDIDCache`] entries.
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

#[derive(Default)]
struct Entries {
    docs: HashMap<String, (u64, Value)>,
    order: BTreeMap<u64, String>,
    clock: u64,
}

impl Entries {
    fn touch(&mut self, short_form: &str, doc: Value) {
        if let Some((tick, _)) = self.docs.remove(short_form) {
            self.order.remove(&tick);
        }
        self.clock += 1;
        self.order.insert(self.clock, short_form.to_owned());
        self.docs.insert(short_form.to_owned(), (self.clock, doc));
    }
}

/// An in-memory [`DIDCache`] that checks the short form against each document it stores and evicts
/// the least recently used entry beyond its bound (`createInMemoryDIDCache`).
pub struct InMemoryDIDCache {
    max_entries: usize,
    entries: Mutex<Entries>,
}

impl InMemoryDIDCache {
    /// A cache holding at most `max_entries` documents (at least 1).
    pub fn new(max_entries: usize) -> Result<Self, TokenError> {
        if max_entries < 1 {
            return Err(TokenError::invalid(
                "DIDCache: maxEntries must be at least 1",
            ));
        }
        Ok(Self {
            max_entries,
            entries: Mutex::new(Entries::default()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Entries> {
        // A panic while holding the lock leaves the maps consistent: every mutation completes.
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for InMemoryDIDCache {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            entries: Mutex::new(Entries::default()),
        }
    }
}

impl DIDCache for InMemoryDIDCache {
    fn get(&self, short_form: &str) -> Option<Value> {
        let mut entries = self.lock();
        let doc = entries.docs.get(short_form)?.1.clone();
        entries.touch(short_form, doc.clone());
        Some(doc)
    }

    fn set(&self, short_form: &str, doc: &Value) -> Result<(), TokenError> {
        if !peer4::is_peer4(short_form) {
            return Err(TokenError::invalid(
                "DIDCache: short form must be a did:peer:4 identifier",
            ));
        }
        // A caller may hand in any value: this bounds its depth before anything recurses over it,
        // then its size before the linear encode below.
        peer4::assert_doc_within_max_size(doc, DEFAULT_MAX_DOC_SIZE)?;
        if peer4::encode(doc)?.short_form != short_form {
            return Err(TokenError::invalid(
                "DIDCache: short form/doc hash mismatch",
            ));
        }
        let mut entries = self.lock();
        entries.touch(short_form, doc.clone());
        while entries.docs.len() > self.max_entries {
            let Some((_, oldest)) = entries.order.pop_first() else {
                break;
            };
            entries.docs.remove(&oldest);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn doc(id: &str) -> Value {
        json!({ "verificationMethod": [{ "id": id, "type": "Multikey", "publicKeyMultibase": "z" }] })
    }

    #[test]
    fn checks_binding_and_evicts_least_recent() {
        let cache = InMemoryDIDCache::new(2).unwrap();
        let [a, b, c] =
            ["#a", "#b", "#c"].map(|id| (peer4::encode(&doc(id)).unwrap().short_form, doc(id)));
        assert_eq!(
            cache.set(&a.0, &b.1).unwrap_err().to_string(),
            "DIDCache: short form/doc hash mismatch"
        );
        assert!(cache.set("did:key:z", &a.1).is_err());
        cache.set(&a.0, &a.1).unwrap();
        cache.set(&b.0, &b.1).unwrap();
        assert!(cache.get(&a.0).is_some());
        cache.set(&c.0, &c.1).unwrap();
        assert!(cache.get(&b.0).is_none());
        assert!(cache.get(&a.0).is_some());
        assert!(InMemoryDIDCache::new(0).is_err());
    }
}
