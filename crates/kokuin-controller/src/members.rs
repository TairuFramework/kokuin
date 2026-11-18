//! Management members and snapshot validation, as `packages/controller/src/members.ts`.

use std::collections::HashSet;

use kokuin_token::{SignatureAlgorithm, did_key, multibase, normalize_did, peer4};
use serde_json::Value;

use crate::canonical::digest_of_str;
use crate::events::{MemberEntry, key_list, key_target, member_entry};
use crate::keys::{KeyAlgorithm, encode_key, try_decode_key};

/// A non-reset rotate missing either half of its state snapshot (`ROTATE_NEEDS_SNAPSHOT`).
pub const ROTATE_NEEDS_SNAPSHOT: &str = "rotate carries no state snapshot";
/// A snapshot whose shape is wrong (`SNAPSHOT_MALFORMED`).
pub const SNAPSHOT_MALFORMED: &str = "malformed state snapshot";
/// A snapshot member pinning a root key (`SNAPSHOT_MEMBER_KEY_IS_ROOT`).
pub const SNAPSHOT_MEMBER_KEY_IS_ROOT: &str = "snapshot member key is a root key";
/// A snapshot member whose DID does not carry its pin (`SNAPSHOT_MEMBER_DID_MISMATCH`).
pub const SNAPSHOT_MEMBER_DID_MISMATCH: &str = "snapshot member DID does not carry its key";
/// A rotate dropping a checkpointed retired-key denial (`SNAPSHOT_DROPS_RETIRED_KEY`).
pub const SNAPSHOT_DROPS_RETIRED_KEY: &str = "snapshot drops a retired key denial";

/// As long as `resolveKidFromDoc` allows (`MAX_KEY_ENCODED` in `@kokuin/token`).
const MAX_KEY_ENCODED: usize = 64;

/// A signing key a DID carries: its algorithm and raw public key.
type CarriedKey = (SignatureAlgorithm, Vec<u8>);

/// The signing keys a DID carries in its identifier (`signingKeysOf`). `None` both when it carries
/// none (TS `null`) and when it claims to carry one and does not (a TS throw): every caller reads
/// the two alike, as "no match".
fn signing_keys_of(did: &str) -> Option<Vec<CarriedKey>> {
    if did.starts_with("did:key:") {
        return did_key::decode(did).ok().map(|key| vec![key]);
    }
    if !peer4::is_peer4(did) || peer4::short_form(did).ok().as_deref() == Some(did) {
        return None;
    }
    let doc = peer4::decode(did, None).ok()?.doc;
    let mut keys = Vec::new();
    for id in doc.authentication() {
        let Some(method) = doc.verification_method(&Value::String(id.to_owned())) else {
            continue;
        };
        if method.encode_utf16().count() > MAX_KEY_ENCODED {
            continue;
        }
        let Ok(bytes) = multibase::decode(method) else {
            continue;
        };
        if let Some(key) = did_key::algorithm_and_public_key(&bytes) {
            keys.push(key);
        }
    }
    Some(keys)
}

/// Whether `did` carries exactly `key` as its one Ed25519 signing key (`memberCarriesKey`).
pub(crate) fn member_carries_key(did: &str, key: &str) -> bool {
    match signing_keys_of(did) {
        Some(keys) => match keys.as_slice() {
            [(SignatureAlgorithm::EdDSA, public_key)] => {
                encode_key(KeyAlgorithm::EdDSA, public_key) == key
            }
            _ => false,
        },
        _ => false,
    }
}

/// **The** predicate for "this denial targets this membership" (`denialTargetsMember`).
pub(crate) fn denial_targets_member(entry: &str, member: &MemberEntry) -> bool {
    if entry == key_target(&member.key) {
        return true;
    }
    entry.starts_with("did:") && normalize_did(entry) == normalize_did(&member.did)
}

/// Every root key a member pin must stay clear of, for one generation (`RootKeySet`).
pub(crate) struct RootKeySet {
    pub keys: HashSet<String>,
    /// Digests, as `n` carries them.
    pub commitments: HashSet<String>,
    /// A digest, as `r` carries it.
    pub recovery: String,
}

/// Whether `key` is a root key of the generation `root` describes (`isRootKey`).
pub(crate) fn is_root_key(key: &str, root: &RootKeySet) -> bool {
    if root.keys.contains(key) {
        return true;
    }
    let digest = digest_of_str(key);
    root.commitments.contains(&digest) || digest == root.recovery
}

/// A snapshot as the fold reads it off a rotate: wire values, judged by [`validate_snapshot`].
pub(crate) struct WireSnapshot<'a> {
    pub members: Option<&'a Value>,
    /// `None` when absent; present and `null` is a malformed `removed`.
    pub removed: Option<&'a Value>,
    pub deny: Option<&'a Value>,
}

/// A snapshot that passed [`validate_snapshot`].
pub(crate) struct Snapshot {
    pub members: Vec<MemberEntry>,
    pub removed: Vec<MemberEntry>,
    pub deny: Vec<String>,
}

/// Judge a snapshot against the generation it lands on: the snapshot when it may become the state,
/// else the fold reason (`validateSnapshot`).
pub(crate) fn validate_snapshot(
    snapshot: &WireSnapshot<'_>,
    root: &RootKeySet,
    tombstones: &HashSet<String>,
) -> Result<Snapshot, &'static str> {
    let empty = Vec::new();
    let (Some(members), Some(removed), Some(deny)) = (
        snapshot.members.and_then(Value::as_array),
        match snapshot.removed {
            None => Some(&empty),
            Some(value) => value.as_array(),
        },
        key_list(snapshot.deny),
    ) else {
        return Err(SNAPSHOT_MALFORMED);
    };
    let is_ed25519 =
        |entry: &MemberEntry| matches!(try_decode_key(&entry.key), Some((KeyAlgorithm::EdDSA, _)));
    let mut adds = HashSet::new();
    let mut pins = HashSet::new();
    let mut live = Vec::with_capacity(members.len());
    for value in members {
        let entry = member_entry(value)
            .filter(is_ed25519)
            .ok_or(SNAPSHOT_MALFORMED)?;
        if adds.contains(&entry.add) || pins.contains(&entry.key) {
            return Err(SNAPSHOT_MALFORMED);
        }
        adds.insert(entry.add.clone());
        pins.insert(entry.key.clone());
        live.push(entry);
    }
    let mut gone = Vec::with_capacity(removed.len());
    for value in removed {
        let entry = member_entry(value)
            .filter(is_ed25519)
            .filter(|entry| !adds.contains(&entry.add))
            .ok_or(SNAPSHOT_MALFORMED)?;
        adds.insert(entry.add.clone());
        gone.push(entry);
    }
    if live
        .iter()
        .chain(&gone)
        .any(|entry| is_root_key(&entry.key, root))
    {
        return Err(SNAPSHOT_MEMBER_KEY_IS_ROOT);
    }
    if live
        .iter()
        .chain(&gone)
        .any(|entry| !member_carries_key(&entry.did, &entry.key))
    {
        return Err(SNAPSHOT_MEMBER_DID_MISMATCH);
    }
    let denied: HashSet<&String> = deny.iter().collect();
    if tombstones
        .iter()
        .any(|tombstone| !denied.contains(tombstone))
    {
        return Err(SNAPSHOT_DROPS_RETIRED_KEY);
    }
    Ok(Snapshot {
        members: live,
        removed: gone,
        deny,
    })
}
