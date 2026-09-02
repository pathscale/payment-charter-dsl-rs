//! Evaluating a request (§8.2 – §8.4A).
//!
//! Order matters and is normative: prohibitions first and independently of every limit, then
//! every applicable limit, then the join. Only if no limit applies at all does S24 refuse.

use crate::calendar::fixed_window;
use crate::compiled::*;
use crate::hierarchy::Chain;
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
        /// The charter that imposed the constraint being escalated. H3: a quorum is answered
        /// by the level that imposed it, so the caller has to know which one that was before
        /// it can convene the right people.
        level: String,
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
    /// H1: the minimum over every level in the chain, for the amount dimension, after each
    /// level resolved its own exceptions against this request.
    ///
    /// Reported rather than derivable, because H4 requires an interface to show the effective
    /// ceiling beside the declared one: a child that writes `unlimited` under a parent capped
    /// at 200 a week is capped at 200 a week, and the word on the page says something narrower
    /// than it reads. `None` when no amount limit applied.
    pub effective_ceiling: Option<u64>,
}

/// One level's applicable limits, already resolved against this request.
struct Resolved<'a> {
    /// Index in the chain: 0 is the root, and lower is higher authority.
    depth: usize,
    level: &'a str,
    limit: &'a Limit,
    ceiling: u64,
}

pub struct Engine<'a> {
    /// The chain, root first and leaf last (§8A). A charter with no parent is a chain of one,
    /// and every rule below degenerates correctly at that length rather than being
    /// special-cased — which is what stops the single-document path from drifting.
    chain: Vec<&'a Compiled>,
    /// Limits of the **leaf** superseded by a newer version, which keep enforcing until their
    /// window closes (§8.4A.2). A rename would otherwise mint a fresh accumulator and a fresh
    /// allowance.
    retired: &'a [Limit],
}

impl<'a> Engine<'a> {
    pub fn new(compiled: &'a Compiled) -> Self {
        Self { chain: alloc::vec![compiled], retired: &[] }
    }

    pub fn with_retired(compiled: &'a Compiled, retired: &'a [Limit]) -> Self {
        Self { chain: alloc::vec![compiled], retired }
    }

    /// Evaluate over a linked chain.
    ///
    /// It takes a [`Chain`] rather than a bare slice so that the linkage checks cannot be
    /// skipped. An unlinked list of documents evaluates perfectly happily and answers `allow`
    /// where the real chain answers `deny`, which is the one failure mode of §8A that produces
    /// a payment rather than an error.
    pub fn chained(chain: &Chain<'a>) -> Self {
        Self { chain: chain.levels().to_vec(), retired: &[] }
    }

    pub fn chained_with_retired(chain: &Chain<'a>, retired: &'a [Limit]) -> Self {
        Self { chain: chain.levels().to_vec(), retired }
    }

    /// The document being enforced. Ancestors bound it; this is the one that was installed.
    pub fn leaf(&self) -> &'a Compiled {
        self.chain[self.chain.len() - 1]
    }

    pub fn levels(&self) -> &[&'a Compiled] {
        &self.chain
    }

    /// H1's effective ceiling for a request, without moving anything.
    ///
    /// The read-only half of [`Self::decide`], for an interface that has to show the number
    /// before the agent commits to it.
    pub fn effective_ceiling(&self, req: &Request) -> Option<u64> {
        match self.resolve_chain(req) {
            Ok(rs) => amount_minimum(&rs),
            Err(_) => None,
        }
    }

    /// Decide a request and, when it is not refused outright, move the accumulators.
    pub fn decide(&self, ledger: &mut Ledger, req: &Request) -> Decision {
        // §8.1.5: a pending approval that has run out of time is released first, so its
        // allowance is available to this request rather than held by a dead one.
        ledger.expire_pending(req.at);

        // §8.2.1 and H6 — every prohibition in every document in the chain, before any limit
        // is examined. This is the one construct that unions rather than taking a minimum, and
        // for the same reason H1 takes a minimum: every refusal in the chain is in force at
        // once, no child exception reaches one, and no quorum lifts one.
        let refused: Vec<String> = self
            .chain
            .iter()
            .flat_map(|c| {
                c.prohibitions
                    .iter()
                    .filter(|p| eval(&p.selector, req))
                    .map(|p| self.qualify(&c.charter_id, &p.id))
            })
            .collect();
        if !refused.is_empty() {
            // No accumulator moves, so a prohibited request costs nothing — including no
            // `count`, which would otherwise let an attacker exhaust the legitimate rate
            // budget with requests that were never going to be paid.
            return self.deny(refused, "prohibited");
        }

        let resolved = match self.resolve_chain(req) {
            Ok(r) => r,
            Err(d) => return *d,
        };

        let mut denied_by = Vec::new();
        // H3: the escalation that answers is the one from the level highest in the chain that
        // is imposing a constraint. Ordering by depth is what makes that true — a department's
        // approvers must not satisfy a company's ceiling, and picking whichever limit the
        // iteration reached first would let them.
        let mut escalation: Option<(&Resolved<'a>, &'a Escalation, &'static str)> = None;
        for r in &resolved {
            let key = self.key(r.level, r.limit, req);
            let used = self.exposure(ledger, r.limit, &key, req);
            let draw = draw_of(r.limit, req);

            // §8.2.3 — thresholds compare the *requested* amount, before accumulation.
            for e in &r.limit.escalations {
                let fires = match e.trigger {
                    Trigger::Above(v) => req.amount > v,
                    Trigger::AtLeast(v) => req.amount >= v,
                    Trigger::WhenExhausted => false,
                };
                if fires && is_higher(&escalation, r) {
                    let name = match e.trigger {
                        Trigger::Above(_) => "above",
                        Trigger::AtLeast(_) => "at least",
                        Trigger::WhenExhausted => "when exhausted",
                    };
                    escalation = Some((r, e, name));
                }
            }

            // §8.4 — exhaustion escalates where a `when exhausted` clause exists, and denies
            // otherwise. Collapsing the two would make an empty allowance unappealable.
            //
            // The clause consulted is this limit's own, at this level. That is H3 holding
            // structurally rather than by a check: a level that ran out of allowance and
            // declared no way to appeal is refused, and a deeper level's quorum is never
            // offered the chance to answer for it.
            if used + draw as u128 > r.ceiling as u128 {
                match r.limit.escalations.iter().find(|e| e.trigger == Trigger::WhenExhausted) {
                    Some(e) if is_higher(&escalation, r) => {
                        escalation = Some((r, e, "when exhausted"));
                    }
                    Some(_) => {}
                    None => denied_by.push(self.qualify(r.level, &r.limit.id)),
                }
            }
        }

        // §8.3 — allow < escalate < deny. Any limit denying denies.
        if !denied_by.is_empty() {
            return self.deny(denied_by, "exhausted");
        }

        // Reserve against every applicable limit at every level, whatever the outcome. H2: a
        // payment by the leaf draws down the leaf's allowance, its manager's, its department's
        // and the company's, which is what a company-wide limit means. A pending escalation
        // holds its reservations (§8.1.5).
        let state = match &escalation {
            Some((_, e, _)) => ReservationState::PendingApproval { expires_at: req.at + e.within },
            None => ReservationState::Reserved,
        };
        let mut reservations = Vec::new();
        for r in &resolved {
            let key = self.key(r.level, r.limit, req);
            let releasable = r.limit.dimension == Dimension::Amount;
            reservations.push(ledger.push(key, req.at, draw_of(r.limit, req), state, releasable));
        }

        let outcome = match escalation {
            Some((r, e, name)) => Outcome::Escalate {
                level: String::from(r.level),
                limit: r.limit.id.clone(),
                trigger: name,
                quorum: e.quorum,
                approvers: e.approvers.clone(),
                ceiling: e.ceiling,
            },
            None => Outcome::Allow,
        };
        Decision { outcome, reservations, effective_ceiling: amount_minimum(&resolved) }
    }

    /// Every applicable limit at every level, root first, each resolved against this request.
    ///
    /// Root first is not presentation. H4's `unlimited` means "this level adds no constraint",
    /// and its value is the parent's effective ceiling — so a level can only be resolved once
    /// everything above it has been, and the induction that keeps S5's bound finite runs in
    /// exactly this direction.
    fn resolve_chain(&self, req: &Request) -> Result<Vec<Resolved<'a>>, alloc::boxed::Box<Decision>> {
        let mut out: Vec<Resolved<'a>> = Vec::new();
        // The tightest ceiling imposed so far by strictly shallower levels, per dimension. A
        // child's `unlimited` inherits from the same dimension only: a monthly spending cap is
        // not what bounds a rate, and taking a minimum across the two would compare a number of
        // payments against an amount of money.
        let mut inherited_amount: Option<u64> = None;
        let mut inherited_count: Option<u64> = None;

        for (depth, &c) in self.chain.iter().enumerate() {
            let is_leaf = depth + 1 == self.chain.len();
            let mut level_amount: Option<u64> = None;
            let mut level_count: Option<u64> = None;
            // S24 asks whether the money is bounded, so only an `amount` limit answers it. A
            // `count` applies to every request and bounds none of them in value: a level whose
            // only applicable rule were a rate would authorise any sum at all, twenty times a
            // day.
            let mut bounded = false;

            let limits = c.limits.iter().chain(if is_leaf { self.retired } else { &[] }.iter());
            for limit in limits {
                if !applies(c, limit, req) {
                    continue;
                }
                if limit.dimension == Dimension::Amount {
                    bounded = true;
                }
                let inherited = match limit.dimension {
                    Dimension::Amount => inherited_amount,
                    Dimension::Count => inherited_count,
                };
                let Some(ceiling) = resolve_limit(limit, req, inherited) else {
                    // H4 again: `unlimited` is finite only because a parent bounds it. E314
                    // keeps it out of a root, and this is the case E314 cannot see — a child
                    // whose parent turns out to cap nothing comparable for this request. It
                    // denies rather than defaulting, because the alternative is an unbounded
                    // ceiling reached by writing one word.
                    return Err(alloc::boxed::Box::new(self.deny(
                        alloc::vec![self.qualify(&c.charter_id, &limit.id)],
                        "E315",
                    )));
                };
                match limit.dimension {
                    Dimension::Amount => {
                        level_amount = Some(level_amount.map_or(ceiling, |m: u64| m.min(ceiling)))
                    }
                    Dimension::Count => {
                        level_count = Some(level_count.map_or(ceiling, |m: u64| m.min(ceiling)))
                    }
                }
                out.push(Resolved { depth, level: &c.charter_id, limit, ceiling });
            }

            if !bounded {
                // S24 within a document, H5 across a chain: "matches no rule" must never mean
                // "permitted" in a document whose purpose is to bound spending, and there is no
                // inheritance of permission by omission either. A level that caps nothing
                // applicable to this request has not authorised it.
                let code = if self.chain.len() == 1 { "E219" } else { "E315" };
                let by = if self.chain.len() == 1 {
                    Vec::new()
                } else {
                    alloc::vec![c.charter_id.clone()]
                };
                return Err(alloc::boxed::Box::new(Decision {
                    outcome: Outcome::Deny { by, code },
                    reservations: Vec::new(),
                    effective_ceiling: None,
                }));
            }

            inherited_amount = tighten(inherited_amount, level_amount);
            inherited_count = tighten(inherited_count, level_count);
        }

        Ok(out)
    }

    /// A rule's name, qualified by its level only where there is more than one.
    ///
    /// A single document has no level to name, and qualifying anyway would change what every
    /// existing decision reports for no gain.
    fn qualify(&self, level: &str, id: &str) -> String {
        if self.chain.len() > 1 {
            alloc::format!("{level}.{id}")
        } else {
            String::from(id)
        }
    }

    fn deny(&self, by: Vec<String>, code: &'static str) -> Decision {
        Decision {
            outcome: Outcome::Deny { by, code },
            reservations: Vec::new(),
            effective_ceiling: None,
        }
    }

    fn key(&self, level: &str, limit: &Limit, req: &Request) -> AccumulatorKey {
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
            level: String::from(level),
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
}

/// Is `r` at a level strictly higher in the chain than the escalation already chosen?
///
/// Ties keep the incumbent, so within one level the first firing clause wins and the order of
/// declarations decides — which is the same rule as before a chain existed.
fn is_higher(current: &Option<(&Resolved, &Escalation, &'static str)>, r: &Resolved) -> bool {
    match current {
        None => true,
        Some((c, _, _)) => r.depth < c.depth,
    }
}

fn tighten(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// H1, for the amount dimension: the minimum over every level, after each resolved its own
/// exceptions.
///
/// It reports rather than decides. Every level's accumulator is compared against that level's
/// own ceiling and any level may refuse (§8.3), so the minimum already binds without being
/// computed — this is the number to *show*, and computing it is not what makes it true.
fn amount_minimum(rs: &[Resolved]) -> Option<u64> {
    rs.iter()
        .filter(|r| r.limit.dimension == Dimension::Amount)
        .map(|r| r.ceiling)
        .min()
}


/// S23: does this limit constrain this request?
///
/// For `amount`, the request's asset must be the limit's asset or a member of it when that is
/// a group. For `count` there is no asset to match — a rate bounds how many payments are made
/// and says nothing about what they are denominated in (§8.1.3), and the `#count` placeholder
/// its accumulator is keyed by is a discriminator, not a settlement asset. Gating a count limit
/// on it made every `count` in the language inert, including the one in §4.
///
/// Group membership is read from the declaring level's own document. A department's group and
/// a company's group with the same name are two declarations, and resolving one against the
/// other's members would let a child widen a parent's group by redeclaring it.
fn applies(c: &Compiled, limit: &Limit, req: &Request) -> bool {
    if limit.dimension == Dimension::Amount {
        let asset_matches = limit.asset == req.asset
            || c.asset_groups
                .iter()
                .any(|(g, members)| *g == limit.asset && members.contains(&req.asset));
        if !asset_matches {
            return false;
        }
    }
    match &limit.applies {
        Some(s) => eval(s, req),
        None => true,
    }
}

/// §8.2.2: collect every exception that holds. None means the base; exactly one means its
/// value; more than one is a conflict, and the limit denies rather than paying the first
/// match — an author who writes two exceptions believing them exclusive would otherwise be
/// paid by whichever the parser reached first.
///
/// `inherited` is H4's parent ceiling. `None` back means an `unlimited` with nothing above it
/// to be finite against.
fn resolve_limit(limit: &Limit, req: &Request, inherited: Option<u64>) -> Option<u64> {
    let hits: Vec<&ExcValue> = limit
        .exceptions
        .iter()
        .filter(|(s, _)| eval(s, req))
        .map(|(_, v)| v)
        .collect();
    match hits.len() {
        0 => Some(limit.base),
        1 => match hits[0] {
            ExcValue::Value(v) => Some(*v),
            // The compiled value is the fallback the compiler could see on its own (§9); the
            // chain, which it could not, is authoritative when there is one.
            ExcValue::Unlimited(fallback) => match inherited {
                Some(v) => Some(v),
                None => (*fallback > 0).then_some(*fallback),
            },
        },
        _ => Some(0),
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

/// What one request draws from a limit's accumulator.
///
/// An `amount` limit is a balance and draws the money; a `count` is a rate and draws exactly one
/// attempt, whatever the payment is worth (§8.1.2, §8.1.3). Charging a count limit the money
/// would make `count 3` mean "three minor units a day" — a rate limit that a single ordinary
/// payment exhausts, and one no author would ever see working.
fn draw_of(limit: &Limit, req: &Request) -> u64 {
    match limit.dimension {
        Dimension::Amount => req.amount,
        Dimension::Count => 1,
    }
}
