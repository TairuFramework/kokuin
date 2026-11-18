//! Golden vector parity with `@kokuin/controller`.
//!
//! The vector file is the one `packages/controller/test/golden.test.ts` writes from the real TS fold.
//! Each case names its `kind`, the function run with its `input`. Every case is checked on its own,
//! and a failing run lists the failing cases by name. Values are compared in canonical form, so a
//! number reads the same whichever JSON spelling produced it.

use std::collections::HashSet;
use std::sync::Arc;

use kokuin_controller::{
    ControllerError, ControllerLog, ControllerResolver, EpochLimits, FoldOutcome, KeyState,
    MemoryLogStore, authoritative_log, device_revoke_indices, fold_epoch_detailed, fold_log,
};
use kokuin_token::{
    DIDMethodResolver, MemberQuery, ResolveIssuerHeader, TokenError, VerifyOptions, verify_token,
};
use serde_json::{Value, json};
use sozai_codec::canonical;

const VECTORS: &str = include_str!("../../../packages/controller/test/golden/controller.json");
const CONTEXT: &str = "Controller resolver";

struct Case {
    name: String,
    input: Value,
    expected: Value,
}

fn load() -> Vec<Case> {
    let file: Value = serde_json::from_str(VECTORS).expect("golden file is JSON");
    assert_eq!(file["version"], json!(1), "golden format version");
    let cases: Vec<Case> = file["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| Case {
            name: case["name"].as_str().expect("name").to_owned(),
            input: case["input"].clone(),
            expected: case["expected"].clone(),
        })
        .collect();
    let names: HashSet<&str> = cases.iter().map(|case| case.name.as_str()).collect();
    assert_eq!(names.len(), cases.len(), "duplicate case names");
    cases
}

fn str_of<'a>(input: &'a Value, key: &str) -> Result<&'a str, String> {
    input[key]
        .as_str()
        .ok_or_else(|| format!("input.{key} is not a string"))
}

fn limits(input: &Value) -> EpochLimits {
    match input["limits"]["MAX_EPOCH_EVENTS"].as_u64() {
        Some(max) => EpochLimits {
            max_epoch_events: max as usize,
        },
        None => EpochLimits::default(),
    }
}

fn controller_error(error: &ControllerError) -> Value {
    json!({ "error": error.name(), "message": error.message() })
}

fn token_error(error: &TokenError) -> Value {
    json!({ "error": error.name(), "message": error.to_string() })
}

fn state(state: &KeyState) -> Value {
    json!({
        "did": state.did,
        "gen": state.generation,
        "seq": state.seq,
        "keyGen": state.key_generation,
        "keySeq": state.key_seq,
        "keys": state.keys,
        "agreement": state.agreement,
        "next": state.next,
        "recovery": state.recovery,
        "deny": state.deny.iter().collect::<Vec<_>>(),
        "members": state.members.values().map(|member| json!({
            "did": member.entry.did,
            "key": member.entry.key,
            "add": member.entry.add,
            "lease": member.entry.lease,
            "removed": member.removed,
            "effective": member.effective,
        })).collect::<Vec<_>>(),
        "tombstones": state.tombstones.values().map(|entry| json!({
            "did": entry.did,
            "key": entry.key,
            "add": entry.add,
            "lease": entry.lease,
        })).collect::<Vec<_>>(),
        "epoch": state.epoch,
        "saturated": state.saturated,
        "digest": state.digest,
    })
}

fn fold(outcome: &FoldOutcome) -> Value {
    match outcome {
        Err(failure) => json!({ "ok": false, "reason": failure.reason, "index": failure.index }),
        Ok(folded) => json!({
            "ok": true,
            "states": folded.states.iter().map(state).collect::<Vec<_>>(),
            "head": state(&folded.head),
            "applied": folded.applied,
            "pending": folded.pending,
            "rejected": folded.rejected,
        }),
    }
}

fn fold_case(input: &Value) -> Result<Value, String> {
    Ok(fold(&fold_log(str_of(input, "did")?, &input["log"])))
}

fn array(value: &Value) -> Vec<Value> {
    value.as_array().cloned().unwrap_or_default()
}

fn epoch_case(input: &Value) -> Result<Value, String> {
    let did = str_of(input, "did")?;
    let chain = fold_log(did, &json!({ "chain": input["chain"], "events": [] }))
        .map_err(|failure| format!("chain does not fold: {}", failure.reason))?;
    let trusted = input.get("trusted").map(array);
    let detail = fold_epoch_detailed(
        did,
        &chain.states,
        &array(&input["events"]),
        trusted.as_deref(),
        limits(input),
    );
    Ok(match detail {
        Err(reason) => json!({ "ok": false, "reason": reason }),
        Ok(detail) => {
            let mut reasons: Vec<(&String, &String)> = detail.reasons.iter().collect();
            reasons.sort();
            json!({
                "ok": true,
                "head": state(&detail.head),
                "applied": detail.applied,
                "pending": detail.pending,
                "rejected": detail.rejected,
                "reasons": reasons.iter().map(|(digest, reason)| json!([digest, reason])).collect::<Vec<_>>(),
                "authentic": detail.applied.iter().filter_map(|digest| {
                    detail.authentic.get(digest).map(|copy| json!([digest, copy["sigs"]]))
                }).collect::<Vec<_>>(),
            })
        }
    })
}

fn seen(input: &Value) -> Result<Option<ControllerLog>, String> {
    match input.get("seen") {
        None => Ok(None),
        Some(value) => ControllerLog::from_value(value)
            .map(Some)
            .ok_or_else(|| "input.seen is not a log".into()),
    }
}

fn authoritative_case(input: &Value) -> Result<Value, String> {
    let did = str_of(input, "did")?;
    let seen = seen(input)?;
    Ok(
        match authoritative_log(did, &input["loaded"], seen.as_ref(), CONTEXT, limits(input)) {
            Ok(settled) => {
                json!({ "log": settled.log.to_value(), "result": fold(&Ok(settled.result)) })
            }
            Err(error) => controller_error(&error),
        },
    )
}

fn resolver(input: &Value, history: bool) -> Result<ControllerResolver, String> {
    let logs = input["logs"].clone();
    let mut resolver =
        ControllerResolver::new(Box::new(move |did: &str| Ok(logs.get(did).cloned())))
            .with_limits(limits(input));
    if history {
        let store = Arc::new(MemoryLogStore::default());
        if let Some(seen) = seen(input)? {
            store.put(str_of(input, "did")?, seen);
        }
        resolver = resolver.with_history(store);
    }
    Ok(resolver)
}

fn hex_key(alg: &str, public_key: &[u8]) -> Value {
    json!({ "alg": alg, "publicKey": hex::encode(public_key) })
}

fn header(call: &Value) -> ResolveIssuerHeader {
    ResolveIssuerHeader {
        kid: call["header"]
            .get("kid")
            .filter(|kid| !kid.is_null())
            .cloned(),
    }
}

fn member(call: &Value) -> Result<MemberQuery, String> {
    let member = &call["member"];
    Ok(MemberQuery {
        did: str_of(member, "did")?.to_owned(),
        add: str_of(member, "add")?.to_owned(),
        generation: member["gen"].as_u64().ok_or("member.gen")?,
    })
}

fn resolve_case(input: &Value) -> Result<Value, String> {
    let did = str_of(input, "did")?;
    let resolver = resolver(input, true)?;
    let call = &input["call"];
    let answer: Result<Value, ControllerError> = match str_of(call, "method")? {
        "resolve" => resolver
            .signing_key(did, &header(call), false)
            .map(|key| hex_key(key.alg.as_str(), &key.public_key)),
        "resolveHistoric" => resolver
            .signing_key(did, &header(call), true)
            .map(|key| hex_key(key.alg.as_str(), &key.public_key)),
        "resolveDenySet" => resolver
            .deny_set(did)
            .map(|deny| json!({ "deny": deny.into_iter().collect::<Vec<_>>() })),
        "resolveAgreementKey" => resolver.agreement_keys(did).map(|keys| {
            json!({ "keys": keys.iter().map(|key| hex_key("X25519", &key.public_key)).collect::<Vec<_>>() })
        }),
        "resolveMember" => resolver.member(did, &member(call)?).map(|member| {
            json!({ "key": hex_key(member.key.alg.as_str(), &member.key.public_key), "lease": member.lease })
        }),
        "resolveMemberHistoric" => resolver.member_historic(did, &member(call)?).map(|historic| {
            json!({
                "key": hex_key(historic.member.key.alg.as_str(), &historic.member.key.public_key),
                "lease": historic.member.lease,
                "removed": historic.removed,
            })
        }),
        other => return Err(format!("unknown method {other}")),
    };
    Ok(answer.unwrap_or_else(|error| controller_error(&error)))
}

fn token_case(input: &Value) -> Result<Value, String> {
    let resolver = resolver(input, false)?;
    let methods: [&dyn DIDMethodResolver; 1] = [&resolver];
    let options = VerifyOptions {
        methods: &methods,
        historic: input["historic"].as_bool().unwrap_or(false),
        ..VerifyOptions::default()
    };
    Ok(match verify_token(str_of(input, "token")?, &options) {
        Ok(verified) => json!({
            "verified": true,
            "publicKey": hex::encode(&verified.public_key),
            "payload": verified.payload,
        }),
        Err(error) => token_error(&error),
    })
}

fn device_revoke_case(input: &Value) -> Result<Value, String> {
    Ok(json!(device_revoke_indices(
        str_of(input, "did")?,
        &array(&input["chain"]),
        str_of(input, "subject")?,
    )))
}

fn run(case: &Case) -> Result<Value, String> {
    let input = &case.input;
    match str_of(input, "kind")? {
        "fold" => fold_case(input),
        "epoch" => epoch_case(input),
        "authoritative" => authoritative_case(input),
        "resolve" => resolve_case(input),
        "token" => token_case(input),
        "deviceRevoke" => device_revoke_case(input),
        other => Err(format!("no runner for kind {other}")),
    }
}

fn same(actual: &Value, expected: &Value) -> bool {
    match (canonical::stringify(actual), canonical::stringify(expected)) {
        (Ok(actual), Ok(expected)) => actual == expected,
        _ => false,
    }
}

#[test]
fn golden_controller() {
    let cases = load();
    assert_eq!(cases.len(), 97, "case count");
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| match run(case) {
            Ok(actual) if same(&actual, &case.expected) => None,
            Ok(actual) => Some(format!(
                "{}: expected {}, got {actual}",
                case.name, case.expected
            )),
            Err(why) => Some(format!("{}: {why}", case.name)),
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} golden cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}
