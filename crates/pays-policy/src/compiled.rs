//! The compiled form (§9) — what the engine evaluates.
//!
//! It carries no text, no spans and no diagnostics. Everything a decision needs is resolved
//! here at compile time, so evaluation performs no lookup and a decision is reproducible in a
//! dispute from the compiled bytes alone.

use crate::calendar::CalUnit;
use crate::Plane;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, Default)]
pub struct Compiled {
    pub charter_id: String,
    pub version: u64,
    pub resolver_tier: String,
    pub resolver_version: u64,
    /// The charter offset in seconds, already resolved from `UTC±HH:MM` (§2.9).
    pub timezone_offset: i32,
    pub assets: Vec<AssetRecord>,
    /// Group name to member names (S22), so S23 applicability is a lookup rather than an
    /// inference. The equivalence itself was checked at compile time and is not rechecked.
    pub asset_groups: Vec<(String, Vec<String>)>,
    pub instruments: Vec<String>,
    pub prohibitions: Vec<Prohibition>,
    pub limits: Vec<Limit>,
    /// S5.1: the sum of the limits' window ceilings per asset — what the whole charter
    /// authorises. Emitted rather than derived, because it is the number a controller wants
    /// and the one no single limit states.
    pub ceiling_document: Vec<(String, u128)>,
}

#[derive(Clone, Debug)]
pub struct AssetRecord {
    pub name: String,
    /// From the resolver. §2.6 refuses more than nine, which is what keeps money in `u64`.
    pub decimals: u8,
}

#[derive(Clone, Debug)]
pub struct Prohibition {
    pub id: String,
    pub selector: Selector,
}

#[derive(Clone, Debug)]
pub struct Limit {
    pub id: String,
    pub dimension: Dimension,
    /// The limit's asset or asset group. An accumulator is keyed by this name (§8.1.1).
    pub asset: String,
    pub base: u64,
    pub exceptions: Vec<(Selector, ExcValue)>,
    /// The compiled `for` clause (S23), absent when the limit declares none. Evaluated first:
    /// a limit whose applicability does not hold is not consulted and its accumulator does not
    /// move.
    pub applies: Option<Selector>,
    pub window: Window,
    pub scope: Scope,
    pub escalations: Vec<Escalation>,
}

impl Limit {
    /// The most this limit permits unaccompanied: the maximum over the base and every
    /// exception value (S5). Prohibitions do not enter the calculation at all.
    pub fn autonomous_ceiling(&self) -> u64 {
        let mut max = self.base;
        for (_, v) in &self.exceptions {
            if let ExcValue::Value(n) = v {
                max = max.max(*n);
            }
        }
        max
    }

    /// The most it permits with a human approving the exact digest, which is the second of the
    /// two numbers a charter states.
    pub fn escalated_ceiling(&self) -> u64 {
        self.escalations.iter().map(|e| e.ceiling).max().unwrap_or(0).max(self.autonomous_ceiling())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dimension {
    /// Reserved at the moment of decision, released only on definite failure (§8.1.2).
    Amount,
    /// Consumed on attempt and **never** released, including on failure — otherwise an agent
    /// with a total failure rate retries without bound (§8.1.3).
    Count,
}

#[derive(Clone, Copy, Debug)]
pub enum ExcValue {
    Value(u64),
    /// H4: resolves to the parent's effective ceiling, finite by induction.
    Unlimited(u64),
}

#[derive(Clone, Copy, Debug)]
pub enum Window {
    Rolling { seconds: i64 },
    Fixed { unit: CalUnit, offset: i32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    None,
    Account,
    Agent,
    Instrument,
    Counterparty,
}

#[derive(Clone, Debug)]
pub struct Escalation {
    pub trigger: Trigger,
    pub quorum: u64,
    pub approvers: String,
    pub ceiling: u64,
    /// Seconds. A pending escalation expires after this and the request is denied (§8.1.5).
    pub within: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// Fires on `requested > v`.
    Above(u64),
    /// Fires on `requested >= v`. The difference from `Above` is one payment, and it is the
    /// one a rule about a round number is most likely to meet (§8.2.3).
    AtLeast(u64),
    /// Fires when `reserved + requested` exceeds the resolved ceiling (§8.4).
    WhenExhausted,
}

/// A compiled condition: a tree over §6's closed field set, with no loops, no recursion and
/// bounded depth. There is no field for accumulated state and a compiler must not provide one
/// (S2), so a selector is a pure function of the request.
#[derive(Clone, Debug)]
pub enum Selector {
    And(alloc::boxed::Box<Selector>, alloc::boxed::Box<Selector>),
    Or(alloc::boxed::Box<Selector>, alloc::boxed::Box<Selector>),
    Not(alloc::boxed::Box<Selector>),
    /// `field is/is not value`, and set membership for `in`/`not in`.
    Is { field: Field, values: Vec<Atom>, negated: bool },
    /// `provenance is at least <plane>` — compares on the taint order, so it keeps holding if
    /// a worse plane is ever added, which an enumerated set would not (W1).
    IsAtLeast { field: Field, plane: Plane },
    Before { date: i32 },
    After { date: i32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Counterparty,
    Asset,
    AssetClass,
    Instrument,
    MerchantCategory,
    MerchantCountry,
    Provenance,
    ProvenanceRecipient,
    ProvenanceAmount,
    ProvenanceAsset,
    ProvenanceVenue,
    Date,
}

impl Field {
    pub fn parse(s: &str) -> Option<Field> {
        Some(match s {
            "counterparty" => Field::Counterparty,
            "asset" => Field::Asset,
            "asset.class" => Field::AssetClass,
            "instrument" => Field::Instrument,
            "merchant.category" => Field::MerchantCategory,
            "merchant.country" => Field::MerchantCountry,
            "provenance" => Field::Provenance,
            "provenance.recipient" => Field::ProvenanceRecipient,
            "provenance.amount" => Field::ProvenanceAmount,
            "provenance.asset" => Field::ProvenanceAsset,
            "provenance.venue" => Field::ProvenanceVenue,
            "date" => Field::Date,
            _ => return None,
        })
    }
}

/// A resolved value in a selector. Group and asset-group names are expanded at compile time,
/// so evaluation never dereferences a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Atom {
    Text(String),
    Plane(Plane),
}
