//! Evaluating a request (§8.2 – §8.4A).
//!
//! Order matters and is normative: prohibitions first and independently of every limit, then
//! every applicable limit, then the join. Only if no limit applies at all does S24 refuse.

use crate::calendar::fixed_window;
use crate::compiled::*;
use crate::{AccumulatorKey, Ledger, Plane, ReservationState, WindowInstance};
use alloc::string::String;
use alloc::vec::Vec;

/// A payment request. Every field is a fact about *this* request; none is accumulated state,
/// which is what S2 guarantees structurally.
#[derive(Clone, Debug, Default)]
pub struct Request {
    /// Epoch seconds, UTC.
    pub at: i64,
    /// Minor units of `asset`.
    pub amount: u64,
    /// The settlement asset's declared name.
    pub asset: String,
    pub instrument: Option<String>,
    pub counterparty: Option<String>,
    pub mcc: Option<String>,
    pub country: Option<String>,
    pub asset_class: Option<String>,
    pub provenance: Provenance,
    pub account: Option<String>,
    pub agent: Option<String>,
    /// Days since the epoch, in the charter's offset — the local calendar date (§2.8).
    pub date: i32,
}

#[derive(Clone, Copy, Debug)]
pub struct Provenance {
    pub recipient: Plane,
    pub amount: Plane,
    pub asset: Plane,
    pub venue: Plane,
}

impl Default for Provenance {
    fn default() -> Self {
        Self {
            recipient: Plane::Principal,
            amount: Plane::Principal,
            asset: Plane::Principal,
            venue: Plane::Principal,
        }
    }
}

impl Provenance {
    /// Bare `provenance` is the tier: the maximum over the four fields, because an intent is
    /// exactly as trustworthy as its worst field (§6.1).
    pub fn tier(&self) -> Plane {
        self.recipient.max(self.amount).max(self.asset).max(self.venue)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    Escalate {
        limit: String,
        trigger: &'static str,
        quorum: u64,
        approvers: String,
        ceiling: u64,
    },
    /// A denial reports **every** rule that refused, not the first (§8.3).
    Deny {
        by: Vec<String>,
        code: &'static str,
    },
}

#[derive(Clone, Debug)]
pub struct Decision {
    pub outcome: Outcome,
    /// Reservation ids created by this decision, for later release or settlement.
    pub reservations: Vec<u64>,
}

pub struct Engine<'a> {
    pub compiled: &'a Compiled,
    /// Limits superseded by a newer version that keep enforcing until their window closes
    /// (§8.4A.2). A rename would otherwise mint a fresh accumulator and a fresh allowance.
    pub retired: &'a [Limit],
}

impl<'a> Engine<'a> {
    pub fn new(compiled: &'a Compiled) -> Self {
        Self { compiled, retired: &[] }
    }

    pub fn with_retired(compiled: &'a Compiled, retired: &'a [Limit]) -> Self {
        Self { compiled, retired }
    }

    /// Decide a request and, when it is not refused outright, move the accumulators.
    pub fn decide(&self, ledger: &mut Ledger, req: &Request) -> Decision {
        // §8.1.5: a pending approval that has run out of time is released first, so its
        // allowance is available to this request rather than held by a dead one.
        ledger.expire_pending(req.at);

        // §8.2.1 — prohibitions, before any limit is examined.
        let refused: Vec<String> = self
            .compiled
            .prohibitions
            .iter()
            .filter(|p| eval(&p.selector, req))
            .map(|p| p.id.clone())
            .collect();
        if !refused.is_empty() {
            // No accumulator moves, so a prohibited request costs nothing — including no
            // `count`, which would otherwise let an attacker exhaust the legitimate rate
            // budget with requests that were never going to be paid.
            return Decision {
                outcome: Outcome::Deny { by: refused, code: "prohibited" },
                reservations: Vec::new(),
            };
        }

        let applicable: Vec<&Limit> = self
            .compiled
            .limits
            .iter()
            .chain(self.retired.iter())
            .filter(|l| self.applies(l, req))
            .collect();

        // S24 — "matches no rule" must never mean "permitted" in a document whose purpose is
        // to bound spending.
        if applicable.is_empty() {
            return Decision {
                outcome: Outcome::Deny { by: Vec::new(), code: "E219" },
                reservations: Vec::new(),
            };
        }

        let mut denied_by = Vec::new();
        let mut escalation: Option<(&Limit, &Escalation, &'static str)> = None;

        for limit in &applicable {
            let key = self.key(limit, req);
            let used = self.exposure(ledger, limit, &key, req);
            let ceiling = self.resolve(limit, req);

            // §8.2.3 — thresholds compare the *requested* amount, before accumulation.
            for e in &limit.escalations {
                let fires = match e.trigger {
                    Trigger::Above(v) => req.amount > v,
                    Trigger::AtLeast(v) => req.amount >= v,
                    Trigger::WhenExhausted => false,
                };
                if fires && escalation.is_none() {
                    let name = match e.trigger {
                        Trigger::Above(_) => "above",
                        Trigger::AtLeast(_) => "at least",
                        Trigger::WhenExhausted => "when exhausted",
                    };
                    escalation = Some((limit, e, name));
                }
            }

            // §8.4 — exhaustion escalates where a `when exhausted` clause exists, and denies
            // otherwise. Collapsing the two would make an empty allowance unappealable.
            if used + req.amount as u128 > ceiling as u128 {
                match limit.escalations.iter().find(|e| e.trigger == Trigger::WhenExhausted) {
                    Some(e) if escalation.is_none() => {
                        escalation = Some((limit, e, "when exhausted"));
                    }
                    Some(_) => {}
                    None => denied_by.push(limit.id.clone()),
                }
            }
        }

        // §8.3 — allow < escalate < deny. Any limit denying denies.
        if !denied_by.is_empty() {
            return Decision {
                outcome: Outcome::Deny { by: denied_by, code: "exhausted" },
                reservations: Vec::new(),
            };
        }

        // Reserve against every applicable limit, whatever the outcome: a pending escalation
        // holds its reservation (§8.1.5).
        let state = match &escalation {
            Some((_, e, _)) => ReservationState::PendingApproval { expires_at: req.at + e.within },
            None => ReservationState::Reserved,
        };
        let mut reservations = Vec::new();
        for limit in &applicable {
            let key = self.key(limit, req);
            reservations.push(ledger.push(key, req.at, req.amount, state));
        }

        let outcome = match escalation {
            Some((l, e, name)) => Outcome::Escalate {
                limit: l.id.clone(),
                trigger: name,
                quorum: e.quorum,
                approvers: e.approvers.clone(),
                ceiling: e.ceiling,
            },
            None => Outcome::Allow,
        };
        Decision { outcome, reservations }
    }

    /// S23: the request's asset is the limit's asset, or a member of it when that is a group,
    /// **and** the `for` condition holds if one is declared.
    fn applies(&self, limit: &Limit, req: &Request) -> bool {
        let asset_matches = limit.asset == req.asset
            || self
                .compiled
                .asset_groups
                .iter()
                .any(|(g, members)| *g == limit.asset && members.iter().any(|m| *m == req.asset));
        if !asset_matches {
            return false;
        }
        match &limit.applies {
            Some(s) => eval(s, req),
            None => true,
        }
    }

    fn key(&self, limit: &Limit, req: &Request) -> AccumulatorKey {
        let scope_value = match limit.scope {
            Scope::None => String::new(),
            Scope::Account => req.account.clone().unwrap_or_default(),
            Scope::Agent => req.agent.clone().unwrap_or_default(),
            Scope::Instrument => req.instrument.clone().unwrap_or_default(),
            Scope::Counterparty => req.counterparty.clone().unwrap_or_default(),
        };
        let window = match limit.window {
            // A rolling window has no instance identity; every reservation is compared against
            // the request's own clock instead.
            Window::Rolling { .. } => WindowInstance(0),
            Window::Fixed { unit, offset } => WindowInstance(fixed_window(req.at, offset, unit)),
        };
        AccumulatorKey {
            limit_id: limit.id.clone(),
            scope_value,
            asset: limit.asset.clone(),
            window,
        }
    }

    fn exposure(&self, ledger: &Ledger, limit: &Limit, key: &AccumulatorKey, req: &Request) -> u128 {
        match limit.window {
            Window::Rolling { seconds } => ledger.exposure_since(key, req.at - seconds),
            Window::Fixed { .. } => ledger.exposure(key),
        }
    }

    /// §8.2.2: collect every exception that holds. None means the base; exactly one means its
    /// value; more than one is a conflict, and the limit denies rather than paying the first
    /// match — an author who writes two exceptions believing them exclusive would otherwise be
    /// paid by whichever the parser reached first.
    fn resolve(&self, limit: &Limit, req: &Request) -> u64 {
        let hits: Vec<&ExcValue> = limit
            .exceptions
            .iter()
            .filter(|(s, _)| eval(s, req))
            .map(|(_, v)| v)
            .collect();
        match hits.len() {
            0 => limit.base,
            1 => match hits[0] {
                ExcValue::Value(v) => *v,
                ExcValue::Unlimited(parent) => *parent,
            },
            _ => 0,
        }
    }
}

/// Evaluate a selector against a request. Pure: no state, no clock beyond the request's own.
pub fn eval(s: &Selector, req: &Request) -> bool {
    match s {
        Selector::And(a, b) => eval(a, req) && eval(b, req),
        Selector::Or(a, b) => eval(a, req) || eval(b, req),
        Selector::Not(a) => !eval(a, req),
        Selector::Is { field, values, negated } => {
            let hit = values.iter().any(|v| atom_matches(*field, v, req));
            hit != *negated
        }
        Selector::IsAtLeast { field, plane } => plane_of(*field, req).is_some_and(|p| p >= *plane),
        Selector::Before { date } => req.date < *date,
        Selector::After { date } => req.date > *date,
    }
}

fn plane_of(field: Field, req: &Request) -> Option<Plane> {
    Some(match field {
        Field::Provenance => req.provenance.tier(),
        Field::ProvenanceRecipient => req.provenance.recipient,
        Field::ProvenanceAmount => req.provenance.amount,
        Field::ProvenanceAsset => req.provenance.asset,
        Field::ProvenanceVenue => req.provenance.venue,
        _ => return None,
    })
}

fn atom_matches(field: Field, atom: &Atom, req: &Request) -> bool {
    if let Some(p) = plane_of(field, req) {
        return matches!(atom, Atom::Plane(q) if *q == p);
    }
    let Atom::Text(want) = atom else { return false };
    let have = match field {
        Field::Counterparty => req.counterparty.as_deref(),
        Field::Asset => Some(req.asset.as_str()),
        Field::AssetClass => req.asset_class.as_deref(),
        Field::Instrument => req.instrument.as_deref(),
        Field::MerchantCategory => req.mcc.as_deref(),
        Field::MerchantCountry => req.country.as_deref(),
        _ => None,
    };
    have == Some(want.as_str())
}
