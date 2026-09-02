//! Evaluates a compiled Payment Charter.
//!
//! **Dependency-free, and it never parses text.** This is the half the enclave links, and the
//! crate split exists so that is true by construction rather than by discipline. It takes a
//! compiled charter (§9) and nothing else; `text_digest` is opaque bytes to it (§12.3).
//!
//! The model is petty cash (§8.1): a limit's allowance is drawn down when a payment is
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

pub use authenticity::{sha256, AuthError, Commitment, Verifier, VersionStore};
pub use compiled::*;
pub use eval::{Decision, Engine, Outcome, Request};

/// The provenance planes, ordered by increasing taint (§6.1).
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
/// (§8.4A). That is the whole of "an edit changes the ceiling, never the meter": installing a
/// new version re-points limits at new ceilings and leaves every accumulator where it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WindowInstance(pub i64);

/// What an accumulator is keyed by (§8.1.1).
///
/// `asset` is the name the limit declares — an `asset` or an `asset group` — and never a
/// `(chain, mint_id)` pair, which is what gives an asset group one accumulator across its
/// members.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccumulatorKey {
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
    pub amount: u64,
    pub state: ReservationState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationState {
    /// Debited. Exposure is counted from here, strictly before any signature exists.
    Reserved,
    /// Awaiting a quorum. It still holds its reservation — otherwise thirty approvals queue
    /// under the ceiling and release together (§8.1.5).
    PendingApproval { expires_at: i64 },
    /// Released on **proof of death**, never on a timeout (§8.1.4).
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

    fn push(&mut self, key: AccumulatorKey, at: i64, amount: u64, state: ReservationState) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.entries.entry(key).or_default().push(Reservation { id, at, amount, state });
        id
    }

    /// Release by id. Callers reach this only on terminal evidence that the money cannot move
    /// — on Solana, blockhash expiry (§8.1.4). It is not a timer.
    pub fn release(&mut self, id: u64) -> bool {
        for rs in self.entries.values_mut() {
            for r in rs.iter_mut() {
                if r.id == id {
                    // A `count` is consumed on attempt and never released, so the caller must
                    // not route count reservations here; the engine keeps them separate.
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

    /// Expire pending approvals whose `within` has elapsed. §8.1.5: on expiry the reservation
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

/// The executable statement of the invariant (§8.5).
///
/// > No execution releases signatures whose aggregate exposure exceeds the charter's limits
/// > over any window, **absent explicit human authorization of the exact payment digest.**
///
/// The qualifier is the claim rather than a retreat from it: the bound is on what an agent does
/// unaccompanied, and every escalation names a finite ceiling, so the human-authorized path is
/// bounded by a literal too.
pub fn check_invariant(compiled: &Compiled, ledger: &Ledger) -> Result<(), String> {
    for key in ledger.keys() {
        let Some(limit) = compiled.limits.iter().find(|l| l.id == key.limit_id) else {
            // A superseded limit keeps enforcing until its window closes (§8.4A.2), so its
            // accumulator outliving its declaration is expected, not a violation.
            continue;
        };
        let ceiling = limit.autonomous_ceiling();
        let escalated = limit.escalated_ceiling();
        let used = ledger.exposure(key);
        if used > escalated.max(ceiling) as u128 {
            return Err(alloc::format!(
                "{} over {}: {} used against a ceiling of {}",
                key.limit_id,
                key.scope_value,
                used,
                escalated.max(ceiling)
            ));
        }
    }
    Ok(())
}
