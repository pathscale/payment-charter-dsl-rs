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
    /// The parent pin (§8A): the charter id and the exact version this document extends.
    ///
    /// Part of the compiled form, and therefore part of §12.3's digest, because a child that
    /// did not carry its parent could be re-parented under a laxer chain with its signature
    /// still verifying. The pin is a version and not a name alone for the same reason.
    pub extends: Option<(String, u64)>,
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

/// A canonical byte encoding of the compiled form (§9).
///
/// > The compiled form MUST be canonical: the same document compiles to byte-identical output
/// > under the same resolver version. This is what makes a decision reproducible in a dispute.
///
/// It is what §12's `compiled_digest` is taken over, so a stable ordering is not a nicety: two
/// engines that serialise the same charter differently produce different digests and reject
/// each other's signatures.
///
/// Text rather than a packed binary, deliberately. It has to be diffed by a person during a
/// dispute, and a line-oriented form is as deterministic as a binary one while remaining
/// something an auditor can read. Every collection is emitted in a defined order and every
/// number in decimal, so there is nothing left to a serialiser's discretion.
pub fn encode(c: &Compiled) -> alloc::vec::Vec<u8> {
    use core::fmt::Write;
    let mut s = String::new();

    let _ = writeln!(s, "charter {} {}", c.charter_id, c.version);
    // The parent pin is part of the digest: a child that did not carry it could be re-parented
    // under a laxer chain with its signature still verifying (§8A, §12.3).
    if let Some((parent, v)) = &c.extends {
        let _ = writeln!(s, "extends {parent} {v}");
    }
    let _ = writeln!(s, "resolver {} {}", c.resolver_tier, c.resolver_version);
    let _ = writeln!(s, "offset {}", c.timezone_offset);

    let mut assets: alloc::vec::Vec<&AssetRecord> = c.assets.iter().collect();
    assets.sort_by(|a, b| a.name.cmp(&b.name));
    for a in assets {
        let _ = writeln!(s, "asset {} {}", a.name, a.decimals);
    }

    let mut groups: alloc::vec::Vec<&(String, alloc::vec::Vec<String>)> =
        c.asset_groups.iter().collect();
    groups.sort_by(|a, b| a.0.cmp(&b.0));
    for (g, members) in groups {
        let mut m = members.clone();
        m.sort();
        let _ = writeln!(s, "asset_group {} {}", g, m.join(","));
    }

    let mut instruments = c.instruments.clone();
    instruments.sort();
    for i in instruments {
        let _ = writeln!(s, "instrument {i}");
    }

    let mut prohibitions: alloc::vec::Vec<&Prohibition> = c.prohibitions.iter().collect();
    prohibitions.sort_by(|a, b| a.id.cmp(&b.id));
    for p in prohibitions {
        let _ = writeln!(s, "prohibit {} {}", p.id, selector(&p.selector));
    }

    let mut limits: alloc::vec::Vec<&Limit> = c.limits.iter().collect();
    limits.sort_by(|a, b| a.id.cmp(&b.id));
    for l in limits {
        let _ = writeln!(
            s,
            "limit {} {} {} {} {} {}",
            l.id,
            match l.dimension {
                Dimension::Amount => "amount",
                Dimension::Count => "count",
            },
            l.asset,
            l.base,
            window(&l.window),
            scope(l.scope),
        );
        if let Some(a) = &l.applies {
            let _ = writeln!(s, "  applies {}", selector(a));
        }
        // Exceptions are emitted in the order the compiler produced, which is source order
        // after S4 has proved them disjoint: nothing about the meaning depends on it, and
        // re-sorting here would hide a compiler that reordered them.
        for (sel, v) in &l.exceptions {
            let _ = writeln!(
                s,
                "  except {} {}",
                match v {
                    ExcValue::Value(n) => *n,
                    ExcValue::Unlimited(n) => *n,
                },
                selector(sel)
            );
        }
        for e in &l.escalations {
            let _ = writeln!(
                s,
                "  escalate {} {} {} {} {}",
                match e.trigger {
                    Trigger::Above(v) => alloc::format!("above:{v}"),
                    Trigger::AtLeast(v) => alloc::format!("atleast:{v}"),
                    Trigger::WhenExhausted => String::from("exhausted"),
                },
                e.quorum,
                e.approvers,
                e.ceiling,
                e.within,
            );
        }
    }

    let mut ceilings = c.ceiling_document.clone();
    ceilings.sort_by(|a, b| a.0.cmp(&b.0));
    for (asset, total) in ceilings {
        let _ = writeln!(s, "ceiling {asset} {total}");
    }

    s.into_bytes()
}

fn window(w: &Window) -> String {
    match w {
        Window::Rolling { seconds } => alloc::format!("rolling:{seconds}"),
        Window::Fixed { unit, offset } => alloc::format!(
            "fixed:{}:{offset}",
            match unit {
                crate::calendar::CalUnit::Day => "day",
                crate::calendar::CalUnit::Week => "week",
                crate::calendar::CalUnit::Month => "month",
                crate::calendar::CalUnit::Year => "year",
            }
        ),
    }
}

fn scope(s: Scope) -> &'static str {
    match s {
        Scope::None => "-",
        Scope::Account => "account",
        Scope::Agent => "agent",
        Scope::Instrument => "instrument",
        Scope::Counterparty => "counterparty",
    }
}

fn selector(s: &Selector) -> String {
    match s {
        Selector::And(a, b) => alloc::format!("(and {} {})", selector(a), selector(b)),
        Selector::Or(a, b) => alloc::format!("(or {} {})", selector(a), selector(b)),
        Selector::Not(a) => alloc::format!("(not {})", selector(a)),
        Selector::Is { field, values, negated } => {
            // Atoms were expanded from groups at compile time, so sorting them here makes the
            // encoding independent of the order a group happened to list its members.
            let mut vs: alloc::vec::Vec<String> = values.iter().map(atom).collect();
            vs.sort();
            alloc::format!(
                "({} {} {})",
                if *negated { "isnot" } else { "is" },
                field_name(*field),
                vs.join(",")
            )
        }
        Selector::IsAtLeast { field, plane } => {
            alloc::format!("(atleast {} {})", field_name(*field), plane.as_str())
        }
        Selector::Before { date } => alloc::format!("(before {date})"),
        Selector::After { date } => alloc::format!("(after {date})"),
    }
}

fn atom(a: &Atom) -> String {
    match a {
        Atom::Text(t) => t.clone(),
        Atom::Plane(p) => String::from(p.as_str()),
    }
}

fn field_name(f: Field) -> &'static str {
    match f {
        Field::Counterparty => "counterparty",
        Field::Asset => "asset",
        Field::AssetClass => "asset.class",
        Field::Instrument => "instrument",
        Field::MerchantCategory => "merchant.category",
        Field::MerchantCountry => "merchant.country",
        Field::Provenance => "provenance",
        Field::ProvenanceRecipient => "provenance.recipient",
        Field::ProvenanceAmount => "provenance.amount",
        Field::ProvenanceAsset => "provenance.asset",
        Field::ProvenanceVenue => "provenance.venue",
        Field::Date => "date",
    }
}
