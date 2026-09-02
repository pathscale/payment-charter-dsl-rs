//! Evaluates a compiled Payment Charter.
//!
//! **Dependency-free, and it never parses text.** This is the half the enclave links, and the
//! crate split exists so that is true by construction rather than by discipline. It takes a
//! compiled charter (Â§9) and nothing else; `text_digest` is opaque bytes to it (Â§12.3).
//!
//! The model is petty cash (Â§8.1): a limit's allowance is drawn down when a payment is
//! committed to, not when it settles. Reserving something that never broadcasts overcounts,
//! which costs liveness and never costs safety. That trade is deliberate.

#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub mod authenticity;
pub mod calendar;
pub mod compiled;
pub mod eval;
pub mod hierarchy;

pub use authenticity::{sha256, AuthError, Commitment, Verifier, VersionStore};
pub use compiled::*;
pub use eval::{Decision, Engine, Outcome, Request};
pub use hierarchy::{Chain, ChainDiagnostic, Severity};

/// The provenance planes, ordered by increasing taint (Â§6.1).
///
/// An intent is exactly as trustworthy as its worst field, so bare `provenance` is the maximum
/// over the four dotted forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Plane {
    Principal,
    Agent,
    Merchant,
    Network,
}

impl Plane {
    pub fn parse(s: &str) -> Option<Plane> {
        Some(match s {
            "principal" => Plane::Principal,
            "agent" => Plane::Agent,
            "merchant" => Plane::Merchant,
            "network" => Plane::Network,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Plane::Principal => "principal",
            Plane::Agent => "agent",
            Plane::Merchant => "merchant",
            Plane::Network => "network",
        }
    }
}

/// A window instance: the identity of the accounting period a payment belongs to.
///
/// Keyed by the wall-clock interval it covers, **not** by the charter version that created it
/// (Â§8.4A). That is the whole of "an edit changes the ceiling, never the meter": installing a
/// new version re-points limits at new ceilings and leaves every accumulator where it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WindowInstance(pub i64);

/// What an accumulator is keyed by (Â§8.1.1), plus the level that owns it (Â§8A H2).
///
/// `asset` is the name the limit declares â an `asset` or an `asset group` â and never a
/// `(chain, mint_id)` pair, which is what gives an asset group one accumulator across its
/// members.
///
/// `level` is the declaring charter's id, not its index in the chain. A charter id is stable
/// across versions (E506 enforces it) and across re-rooting, so an accumulator survives an
/// install for the same reason `window` does: an edit changes the ceiling, never the meter.
/// Indices would not â inserting a level above would silently reset every meter below it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccumulatorKey {
    pub level: String,
    pub limit_id: String,
    pub scope_value: String,
    pub asset: String,
    pub window: WindowInstance,
}

/// A reservation, held from the moment of decision.
#[derive(Clone, Debug)]
pub struct Reservation {
    pub id: u64,
    pub at: i64,
    /// What this reservation draws: minor units for an `amount` limit, and exactly 1 for a
    /// `count`, which meters attempts rather than money.
    pub amount: u64,
    pub state: ReservationState,
    /// False for a `count` (§8.1.3): a rate is consumed on attempt and never returned, and an
    /// agent whose every payment fails would otherwise retry without bound — which is the case
    /// the control exists for. Recorded here rather than left to the caller, because a caller
    /// holding a decision's reservation ids has no way to tell which is which.
    pub releasable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationState {
    /// Debited. Exposure is counted from here, strictly before any signature exists.
    Reserved,
    /// Awaiting a quorum. It still holds its reservation â otherwise thirty approvals queue
    /// under the ceiling and release together (Â§8.1.5).
    PendingApproval { expires_at: i64 },
    /// Released on **proof of death**, never on a timeout (Â§8.1.4).
    Released,
    Settled,
}

impl Reservation {
    fn counts(&self) -> bool {
        !matches!(self.state, ReservationState::Released)
    }
}

/// Durable state, one map. An engine is a pure function of this plus the compiled charter.
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    entries: BTreeMap<AccumulatorKey, Vec<Reservation>>,
    next_id: u64,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Exposure against a key: everything reserved-or-later, which is what the invariant
    /// bounds. A pending escalation counts; only proof of death removes anything.
    pub fn exposure(&self, key: &AccumulatorKey) -> u128 {
        self.entries
            .get(key)
            .map(|rs| rs.iter().filter(|r| r.counts()).map(|r| r.amount as u128).sum())
            .unwrap_or(0)
    }

    /// Exposure within a rolling window ending at `now`.
    pub fn exposure_since(&self, key: &AccumulatorKey, since: i64) -> u128 {
        self.entries
            .get(key)
            .map(|rs| {
                rs.iter()
                    .filter(|r| r.counts() && r.at > since)
                    .map(|r| r.amount as u128)
                    .sum()
            })
            .unwrap_or(0)
    }

    fn push(
        &mut self,
        key: AccumulatorKey,
        at: i64,
        amount: u64,
        state: ReservationState,
        releasable: bool,
    ) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.entries
            .entry(key)
            .or_default()
            .push(Reservation { id, at, amount, state, releasable });
        id
    }

    /// Release by id. Callers reach this only on terminal evidence that the money cannot move
    /// â on Solana, blockhash expiry (Â§8.1.4). It is not a timer.
    /// Returns whether the reservation is now released. A `count` reservation answers `false`
    /// and is left alone: §8.1.3 gives no evidence that returns a rate, so this is refused
    /// structurally rather than documented as something a caller must remember.
    pub fn release(&mut self, id: u64) -> bool {
        for rs in self.entries.values_mut() {
            for r in rs.iter_mut() {
                if r.id == id {
                    if !r.releasable {
                        return false;
                    }
                    r.state = ReservationState::Released;
                    return true;
                }
            }
        }
        false
    }

    pub fn settle(&mut self, id: u64) -> bool {
        for rs in self.entries.values_mut() {
            for r in rs.iter_mut() {
                if r.id == id {
                    r.state = ReservationState::Settled;
                    return true;
                }
            }
        }
        false
    }

    /// Expire pending approvals whose `within` has elapsed. Â§8.1.5: on expiry the reservation
    /// is released and the request is denied.
    pub fn expire_pending(&mut self, now: i64) -> Vec<u64> {
        let mut expired = Vec::new();
        for rs in self.entries.values_mut() {
            for r in rs.iter_mut() {
                if let ReservationState::PendingApproval { expires_at } = r.state {
                    if now >= expires_at {
                        r.state = ReservationState::Released;
                        expired.push(r.id);
                    }
                }
            }
        }
        expired
    }

    pub fn keys(&self) -> impl Iterator<Item = &AccumulatorKey> {
        self.entries.keys()
    }
}

/// The executable statement of the invariant (Â§8.5).
///
/// > No execution releases signatures whose aggregate exposure exceeds the charter's limits
/// > over any window, **absent explicit human authorization of the exact payment digest.**
///
/// The qualifier is the claim rather than a retreat from it: the bound is on what an agent does
/// unaccompanied, and every escalation names a finite ceiling, so the human-authorized path is
/// bounded by a literal too.
pub fn check_invariant(compiled: &Compiled, ledger: &Ledger) -> Result<(), String> {
    check_invariant_chain(&crate::hierarchy::Chain::single(compiled), ledger)
}

/// The same statement over a chain (Â§8A H2).
///
/// A chain-aware check is not a convenience. Every level owns accumulators, and a check that
/// knew only the leaf would find no declaration for an ancestor's key, take it for a limit
/// retired under Â§8.4A.2, and skip it â reporting that a company-wide ceiling holds precisely
/// because it never looked at it.
pub fn check_invariant_chain(
    chain: &crate::hierarchy::Chain<'_>,
    ledger: &Ledger,
) -> Result<(), String> {
    for key in ledger.keys() {
        let found = chain
            .depth_of(&key.level)
            .and_then(|d| chain.levels()[d].limits.iter().find(|l| l.id == key.limit_id).map(|l| (d, l)));
        let Some((depth, limit)) = found else {
            // A superseded limit keeps enforcing until its window closes (Â§8.4A.2), so its
            // accumulator outliving its declaration is expected, not a violation.
            continue;
        };
        // The chain's number, not the document's: H4 lets `unlimited` resolve above anything
        // written here.
        let ceiling = chain.static_ceiling(depth, limit);
        let used = ledger.exposure(key);
        if used > ceiling as u128 {
            return Err(alloc::format!(
                "{} at {} over {}: {} used against a ceiling of {}",
                key.limit_id,
                key.level,
                key.scope_value,
                used,
                ceiling
            ));
        }
    }
    Ok(())
}
