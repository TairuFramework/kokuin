//! Branch selection between root chains, as `packages/controller/src/supersede.ts`.

use std::collections::HashSet;

use serde_json::Value;

use crate::canonical::digest_of;
use crate::fold::{KeyState, fold_chain};
use crate::js::prop;
use crate::log::{snapshot_entries, unchanged_entries};

/// Where two branches disagree (`Duplicity`).
#[derive(Clone, Debug, PartialEq)]
pub struct Duplicity {
    /// Generation of the divergence, or `-1` for a failure that is not a fork.
    pub generation: f64,
    /// Sequence of the divergence, or `-1`.
    pub seq: f64,
    /// The two conflicting digests at the divergence, sorted.
    pub digests: [String; 2],
}

/// Why branch selection named no winner (`ResolveFailure`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveFailure {
    /// Two events the controller cannot both have authored at one position.
    Duplicity,
    /// Nothing presented folded.
    NoValidBranch,
}

/// What [`resolve_branches`] answers (`ResolveResult`).
#[derive(Clone, Debug, PartialEq)]
pub enum ResolveResult {
    /// The authoritative chain, and how many state-advancing events losers carried.
    Winner {
        /// The winning chain.
        winner: Vec<Value>,
        /// Discarded events of losing chains.
        superseded: usize,
    },
    /// No winner.
    Failed {
        /// Why.
        failure: ResolveFailure,
        /// Where, for a duplicity.
        duplicity: Duplicity,
    },
}

fn no_position() -> Duplicity {
    Duplicity {
        generation: -1.0,
        seq: -1.0,
        digests: [String::new(), String::new()],
    }
}

#[derive(Clone)]
struct FoldedBranch {
    /// Which presented chain this is.
    source: usize,
    branch: Vec<Value>,
    states: Vec<KeyState>,
    spine: Vec<usize>,
}

impl FoldedBranch {
    fn head(&self) -> &KeyState {
        // A folded chain has at least its inception's state.
        &self.states[self.states.len() - 1]
    }

    fn spine_digest(&self, j: usize) -> &str {
        &self.states[self.spine[j]].digest
    }
}

fn branch_from(source: usize, branch: Vec<Value>, states: Vec<KeyState>) -> FoldedBranch {
    let mut spine = vec![0];
    for i in 1..states.len() {
        if states[i].digest != states[i - 1].digest {
            spine.push(i);
        }
    }
    FoldedBranch {
        source,
        branch,
        states,
        spine,
    }
}

fn last_digest(folded: &FoldedBranch) -> String {
    folded
        .branch
        .last()
        .and_then(|entry| prop(entry, "event"))
        .map(digest_of)
        .unwrap_or_default()
}

/// Which of two branches folding to one head to keep: a total order (`preferred`).
fn preferred(candidate: &FoldedBranch, incumbent: &FoldedBranch) -> bool {
    if candidate.branch.len() != incumbent.branch.len() {
        return candidate.branch.len() < incumbent.branch.len();
    }
    last_digest(candidate) < last_digest(incumbent)
}

fn common_spine(a: &FoldedBranch, b: &FoldedBranch) -> usize {
    let shortest = a.spine.len().min(b.spine.len());
    let mut j = 0;
    while j < shortest && a.spine_digest(j) == b.spine_digest(j) {
        j += 1;
    }
    j
}

/// Walk the contenders down to one, deciding at each divergence (`resolveContenders`).
fn resolve_contenders(mut group: Vec<FoldedBranch>) -> Result<FoldedBranch, Duplicity> {
    while group.len() > 1 {
        let pivot = &group[0];
        let divergence = group[1..]
            .iter()
            .map(|folded| common_spine(pivot, folded))
            .fold(pivot.spine.len(), usize::min);
        let extended: Vec<FoldedBranch> = group
            .iter()
            .filter(|folded| folded.spine.len() > divergence)
            .cloned()
            .collect();
        if extended.is_empty() {
            break;
        }
        if extended.len() < group.len() {
            group = extended;
            continue;
        }
        let mut digests: Vec<&str> = group
            .iter()
            .map(|folded| folded.spine_digest(divergence))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        digests.sort_unstable();
        let (Some(first), Some(second)) = (digests.first(), digests.get(1)) else {
            break;
        };
        let (first, second) = ((*first).to_owned(), (*second).to_owned());
        let reporter = group
            .iter()
            .find(|folded| folded.spine_digest(divergence) == first)
            .unwrap_or(&group[0]);
        let at = &reporter.states[reporter.spine[divergence]];
        return Err(Duplicity {
            generation: at.generation,
            seq: at.seq,
            digests: [first, second],
        });
    }
    group.into_iter().next().ok_or_else(no_position)
}

/// Pick the authoritative root chain among `chains` (`resolveBranches`): the highest folded
/// generation wins; within it, chains are compared where they diverge.
pub fn resolve_branches(did: &str, chains: &[Vec<Value>]) -> ResolveResult {
    let snapshots: Vec<Vec<Value>> = chains.iter().map(|chain| snapshot_entries(chain)).collect();
    let valid: Vec<FoldedBranch> = snapshots
        .iter()
        .enumerate()
        .filter_map(|(source, branch)| {
            fold_chain(did, branch)
                .ok()
                .map(|states| branch_from(source, branch.clone(), states))
        })
        .collect();
    match select_winner(valid) {
        Ok((source, superseded)) => {
            let snapshot = &snapshots[source];
            // The presented chain itself when snapshotting changed nothing it carries.
            let winner = if unchanged_entries(snapshot, &chains[source]) {
                chains[source].clone()
            } else {
                snapshot.clone()
            };
            ResolveResult::Winner { winner, superseded }
        }
        Err(failed) => failed,
    }
}

fn failed(failure: ResolveFailure, duplicity: Duplicity) -> ResolveResult {
    ResolveResult::Failed { failure, duplicity }
}

/// The winning chain's index among those presented, and the superseded count.
fn select_winner(valid: Vec<FoldedBranch>) -> Result<(usize, usize), ResolveResult> {
    if valid.is_empty() {
        return Err(failed(ResolveFailure::NoValidBranch, no_position()));
    }
    let mut by_head: Vec<FoldedBranch> = Vec::new();
    for folded in valid {
        let digest = folded.head().digest.clone();
        match by_head.iter_mut().find(|kept| kept.head().digest == digest) {
            Some(kept) => {
                if preferred(&folded, kept) {
                    *kept = folded;
                }
            }
            None => by_head.push(folded),
        }
    }
    let distinct = by_head;
    let top = distinct
        .iter()
        .map(|folded| folded.head().generation)
        .fold(f64::NEG_INFINITY, f64::max);
    let contenders: Vec<FoldedBranch> = distinct
        .iter()
        .filter(|folded| folded.head().generation == top)
        .map(|folded| {
            let start = folded
                .spine
                .iter()
                .position(|&index| folded.states[index].generation == top)
                .unwrap_or(0);
            FoldedBranch {
                spine: folded.spine[start..].to_vec(),
                ..folded.clone()
            }
        })
        .collect();
    let trimmed = match resolve_contenders(contenders) {
        Ok(winner) => winner,
        Err(duplicity) => {
            let failure = if duplicity.generation < 0.0 {
                ResolveFailure::NoValidBranch
            } else {
                ResolveFailure::Duplicity
            };
            return Err(failed(failure, duplicity));
        }
    };
    let Some(winner) = distinct
        .iter()
        .find(|folded| folded.source == trimmed.source)
    else {
        return Err(failed(ResolveFailure::NoValidBranch, no_position()));
    };
    let kept: HashSet<&str> = (0..winner.spine.len())
        .map(|j| winner.spine_digest(j))
        .collect();
    let superseded = distinct
        .iter()
        .filter(|loser| loser.source != winner.source)
        .map(|loser| {
            (0..loser.spine.len())
                .filter(|&j| !kept.contains(loser.spine_digest(j)))
                .count()
        })
        .sum();
    Ok((winner.source, superseded))
}
