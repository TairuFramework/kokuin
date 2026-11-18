//! The `did:kokuin:` resolver, as `packages/controller/src/resolver.ts`.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::Arc;

use kokuin_token::{
    DIDMethodResolver, MemberQuery, MethodError, ResolveIssuerHeader, ResolvedAgreementKey,
    ResolvedHistoricMember, ResolvedMember, ResolvedSigningKey,
};
use serde_json::Value;

use crate::ControllerError;
use crate::canonical::{dismantle, within_input_depth};
use crate::epoch::EpochLimits;
use crate::events::DID_PREFIX;
use crate::history::{LogStore, authoritative_log};
use crate::js::prop;
use crate::log::MALFORMED_LOG;
use crate::state_resolver::{
    DID_METHOD, EPOCH_SATURATED, FoldedView, agreement_keys_from, deny_set_from,
    historic_member_from, member_from, signing_key_from,
};

const CONTEXT: &str = "Controller resolver";

/// Loads a controller's whole log as JSON, `None` when the DID is unknown (`loadLog`). An error is
/// reported as a plain error carrying its message.
///
/// The value may be untrusted: one nesting deeper than `MAX_INPUT_DEPTH` containers is taken apart
/// without recursion and refused as `malformed log`, before anything clones, compares or drops it.
pub type LoadLog = Box<dyn Fn(&str) -> Result<Option<Value>, String>>;

/// A `did:kokuin:` resolver (`createControllerResolver`).
///
/// Every answer re-reads and re-folds the log, so a revoke landing between two resolutions takes
/// effect. With a [`LogStore`], a log behind the one accepted before is refused. Every answer comes
/// from the head except `resolve_historic`; while the epoch is saturated, every answer refuses.
pub struct ControllerResolver {
    load_log: LoadLog,
    history: Option<Arc<dyn LogStore>>,
    limits: EpochLimits,
}

impl ControllerResolver {
    /// A resolver over `load_log`, with no memory.
    pub fn new(load_log: LoadLog) -> Self {
        Self {
            load_log,
            history: None,
            limits: EpochLimits::default(),
        }
    }

    /// Remember the last log accepted for each DID in `history`, and refuse one behind it.
    pub fn with_history(mut self, history: Arc<dyn LogStore>) -> Self {
        self.history = Some(history);
        self
    }

    /// Fold under lowered epoch limits. Test-only in TS (`createControllerResolverWithin`).
    pub fn with_limits(mut self, limits: EpochLimits) -> Self {
        self.limits = limits;
        self
    }

    /// A view that loads and folds each DID at most once and answers every question from that
    /// fold (`frozen`). Use one per verification.
    pub fn frozen(&self) -> FrozenResolver<'_> {
        FrozenResolver {
            parent: self,
            views: RefCell::new(HashMap::new()),
        }
    }

    /// Load, fold and check the log for `did` (`loadView`, `computeView`).
    fn compute_view(&self, did: &str) -> Result<FoldedView, ControllerError> {
        let unknown = || ControllerError::plain(format!("Unknown DID: {did}"));
        if !did.starts_with(DID_PREFIX) {
            return Err(unknown());
        }
        let log = match (self.load_log)(did).map_err(ControllerError::plain)? {
            None | Some(Value::Null) => return Err(unknown()),
            Some(log) => log,
        };
        if prop(&log, "events").is_some_and(Value::is_array)
            && prop(&log, "chain")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        {
            return Err(unknown());
        }
        // This resolver owns the loaded value and drops it, so one too deep for a recursive drop is
        // taken apart here and refused as `authoritative_log` refuses it.
        if !within_input_depth(&log) {
            dismantle(log);
            return Err(ControllerError::plain(format!(
                "{CONTEXT}: invalid log for {did}: {MALFORMED_LOG} at event 0"
            )));
        }
        let Some(history) = &self.history else {
            let settled = authoritative_log(did, &log, None, CONTEXT, self.limits)?;
            return Ok(FoldedView {
                states: settled.result.states,
                head: settled.result.head,
            });
        };
        let mut view = None;
        history.merge(did, &mut |seen| {
            let settled = authoritative_log(did, &log, seen, CONTEXT, self.limits)?;
            view = Some(FoldedView {
                states: settled.result.states,
                head: settled.result.head,
            });
            Ok(settled.log)
        })?;
        view.ok_or_else(|| {
            ControllerError::plain(format!(
                "{CONTEXT}: the log store did not run the merge for {did}"
            ))
        })
    }
}

/// A view of a [`ControllerResolver`] that folds each DID at most once (`frozen()`).
pub struct FrozenResolver<'a> {
    parent: &'a ControllerResolver,
    views: RefCell<HashMap<String, Rc<FoldedView>>>,
}

/// Where a resolver's views come from: folded afresh, or frozen at the first fold.
trait Views {
    fn view(&self, did: &str) -> Result<Rc<FoldedView>, ControllerError>;

    /// The view, refused while the epoch is saturated (`resolverOver`'s `live`).
    fn live(&self, did: &str) -> Result<Rc<FoldedView>, ControllerError> {
        let view = self.view(did)?;
        if view.head.saturated {
            return Err(ControllerError::plain(format!("{EPOCH_SATURATED}: {did}")));
        }
        Ok(view)
    }
}

impl Views for ControllerResolver {
    fn view(&self, did: &str) -> Result<Rc<FoldedView>, ControllerError> {
        self.compute_view(did).map(Rc::new)
    }
}

impl Views for FrozenResolver<'_> {
    fn view(&self, did: &str) -> Result<Rc<FoldedView>, ControllerError> {
        if let Some(view) = self.views.borrow().get(did) {
            return Ok(Rc::clone(view));
        }
        // A failed load is no answer to freeze: nothing is kept, so a later call loads afresh.
        let view = Rc::new(self.parent.compute_view(did)?);
        self.views
            .borrow_mut()
            .insert(did.to_owned(), Rc::clone(&view));
        Ok(view)
    }
}

/// The answers [`ControllerResolver`] and [`FrozenResolver`] share (`resolverOver`).
macro_rules! answers {
    ($type:ty) => {
        impl $type {
            /// The key `header` names: the head's for `historic: false` (`resolve`), any of the
            /// current generation's for `historic: true` (`resolveHistoric`).
            pub fn signing_key(
                &self,
                did: &str,
                header: &ResolveIssuerHeader,
                historic: bool,
            ) -> Result<ResolvedSigningKey, ControllerError> {
                signing_key_from(did, &*self.live(did)?, header, historic)
            }

            /// What the head denies, raw and in canonical DID form (`resolveDenySet`).
            pub fn deny_set(&self, did: &str) -> Result<BTreeSet<String>, ControllerError> {
                Ok(deny_set_from(&self.live(did)?.head))
            }

            /// The head's unrevoked key agreement keys (`resolveAgreementKey`).
            pub fn agreement_keys(
                &self,
                did: &str,
            ) -> Result<Vec<ResolvedAgreementKey>, ControllerError> {
                agreement_keys_from(did, &self.live(did)?.head)
            }

            /// The key and lease the head pins for a live member (`resolveMember`).
            pub fn member(
                &self,
                subject: &str,
                query: &MemberQuery,
            ) -> Result<ResolvedMember, ControllerError> {
                member_from(subject, &self.live(subject)?.head, query)
            }

            /// Incarnation evidence for a member of the current generation
            /// (`resolveMemberHistoric`).
            pub fn member_historic(
                &self,
                subject: &str,
                query: &MemberQuery,
            ) -> Result<ResolvedHistoricMember, ControllerError> {
                historic_member_from(subject, &*self.live(subject)?, query)
            }
        }

        impl DIDMethodResolver for $type {
            fn method(&self) -> &str {
                DID_METHOD
            }

            fn resolve(
                &self,
                did: &str,
                header: &ResolveIssuerHeader,
            ) -> Result<ResolvedSigningKey, MethodError> {
                self.signing_key(did, header, false)
                    .map_err(MethodError::from)
            }

            fn resolve_historic(
                &self,
                did: &str,
                header: &ResolveIssuerHeader,
            ) -> Option<Result<ResolvedSigningKey, MethodError>> {
                Some(
                    self.signing_key(did, header, true)
                        .map_err(MethodError::from),
                )
            }

            fn resolve_agreement_key(
                &self,
                did: &str,
            ) -> Option<Result<Vec<ResolvedAgreementKey>, MethodError>> {
                Some(self.agreement_keys(did).map_err(MethodError::from))
            }

            fn resolve_deny_set(&self, did: &str) -> Option<Result<BTreeSet<String>, MethodError>> {
                Some(self.deny_set(did).map_err(MethodError::from))
            }

            fn resolve_member(
                &self,
                subject: &str,
                member: &MemberQuery,
            ) -> Option<Result<ResolvedMember, MethodError>> {
                Some(self.member(subject, member).map_err(MethodError::from))
            }

            fn resolve_member_historic(
                &self,
                subject: &str,
                member: &MemberQuery,
            ) -> Option<Result<ResolvedHistoricMember, MethodError>> {
                Some(
                    self.member_historic(subject, member)
                        .map_err(MethodError::from),
                )
            }
        }
    };
}

answers!(ControllerResolver);
answers!(FrozenResolver<'_>);

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::canonical::MAX_INPUT_DEPTH;
    use crate::fold::fold_log;

    /// A log whose one chain entry nests `depth` arrays deep, built without recursion.
    fn deep_log(depth: usize) -> Value {
        let mut inner = json!(0);
        for _ in 0..depth {
            inner = Value::Array(vec![inner]);
        }
        // Not `json!`: it serializes an interpolated value, recursively.
        let mut log = serde_json::Map::new();
        log.insert("chain".into(), Value::Array(vec![inner]));
        log.insert("events".into(), json!([]));
        Value::Object(log)
    }

    #[test]
    fn over_deep_logs_are_malformed_without_recursion() {
        let deep = deep_log(200_000);
        let failure = fold_log("did:kokuin:zX", &deep).unwrap_err();
        assert_eq!((failure.reason.as_str(), failure.index), (MALFORMED_LOG, 0));
        dismantle(deep);

        let resolver = ControllerResolver::new(Box::new(|_| Ok(Some(deep_log(200_000)))));
        let error = resolver
            .signing_key("did:kokuin:zX", &ResolveIssuerHeader::default(), false)
            .unwrap_err();
        assert_eq!(
            error.message(),
            "Controller resolver: invalid log for did:kokuin:zX: malformed log at event 0"
        );
    }

    #[test]
    fn a_log_within_the_bound_refuses_only_its_over_deep_entry() {
        // Object, chain array and entry use three levels, so this nests exactly to the bound.
        let log = deep_log(MAX_INPUT_DEPTH - 2);
        let failure = fold_log("did:kokuin:zX", &log).unwrap_err();
        assert_eq!(
            (failure.reason.as_str(), failure.index),
            ("malformed event", 0)
        );
    }
}
