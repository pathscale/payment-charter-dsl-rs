//! AST to compiled form (§9).
//!
//! Everything a decision needs is resolved here, so evaluation performs no lookup: group
//! members are expanded, names are dereferenced, money is converted to minor units, offsets
//! are turned into seconds and dates into days.
//!
//! Compilation is where the resolver would supply `decimals`, `class` and the rest. Until
//! that pass exists, [`Resolver`] is supplied by the caller and a missing entry is an error
//! rather than a guess — an assumed scale is a wrong payment.

use crate::ast::{self, Charter, Decl};
use crate::diag::Diagnostic;
use pays_policy::calendar::{days_from_civil, CalUnit};
use pays_policy::compiled::*;
use pays_policy::Plane;
use std::collections::HashMap;

/// What the resolver would supply. Deliberately the minimum the engine needs.
#[derive(Clone, Debug, Default)]
pub struct Resolver {
    pub decimals: HashMap<String, u8>,
}

impl Resolver {
    /// A resolver that reports the same scale for every asset. For tests and for fixtures
    /// whose subject is not the scale; never for production, where a wrong scale is a wrong
    /// payment by a factor of ten.
    pub fn uniform(decimals: u8) -> Self {
        Self { decimals: HashMap::new() }.with_default(decimals)
    }

    fn with_default(mut self, d: u8) -> Self {
        self.decimals.insert(String::from("*"), d);
        self
    }

    fn get(&self, asset: &str) -> Option<u8> {
        self.decimals.get(asset).or_else(|| self.decimals.get("*")).copied()
    }
}

pub fn compile(c: &Charter, r: &Resolver) -> Result<Compiled, Vec<Diagnostic>> {
    let mut errors = Vec::new();
    let offset = offset_seconds(&c.timezone.node);

    let mut assets = Vec::new();
    for d in &c.decls {
        if let Decl::Asset(a) = d {
            match r.get(&a.name.node) {
                // §2.6: more than nine decimals is refused, never truncated.
                Some(dec) if dec > 9 => errors.push(Diagnostic::error(
                    "E223",
                    format!(
                        "`{}` reports {dec} decimals. More than nine is not usable: it is what \
                         keeps money inside u64, where an eighteen-decimal asset tops out at \
                         18.44 tokens (§2.6).",
                        a.name.node
                    ),
                    a.name.span.clone(),
                )),
                Some(dec) => assets.push(AssetRecord { name: a.name.node.clone(), decimals: dec }),
                None => errors.push(Diagnostic::error(
                    "E402",
                    format!("`{}` does not resolve; \"never seen\" and \"fine\" must not produce the same outcome (S7)", a.name.node),
                    a.name.span.clone(),
                )),
            }
        }
    }

    let scale: HashMap<&str, u8> =
        assets.iter().map(|a| (a.name.as_str(), a.decimals)).collect();

    let asset_groups: Vec<(String, Vec<String>)> = c
        .decls
        .iter()
        .filter_map(|d| match d {
            Decl::AssetGroup(g) => Some((
                g.name.node.clone(),
                g.members.iter().map(|m| m.node.clone()).collect(),
            )),
            _ => None,
        })
        .collect();

    // A group's scale is its members': S22 has already checked they agree.
    let mut scale_of = |asset: &str| -> Option<u8> {
        if let Some(d) = scale.get(asset) {
            return Some(*d);
        }
        asset_groups
            .iter()
            .find(|(g, _)| g == asset)
            .and_then(|(_, m)| m.first())
            .and_then(|m| scale.get(m.as_str()).copied())
    };

    let groups: HashMap<&str, Vec<Atom>> = c
        .decls
        .iter()
        .filter_map(|d| match d {
            Decl::Group(g) => Some((
                g.name.node.as_str(),
                g.members.iter().map(|m| Atom::Text(m.node.to_string())).collect(),
            )),
            _ => None,
        })
        .collect();

    let mut prohibitions = Vec::new();
    let mut limits = Vec::new();

    for d in &c.decls {
        match d {
            Decl::Prohibit(p) => match selector(&p.condition, &groups, &asset_groups, offset) {
                Ok(s) => prohibitions.push(Prohibition { id: p.name.node.clone(), selector: s }),
                Err(e) => errors.push(e),
            },
            Decl::Limit(l) => {
                match compile_limit(l, &groups, &asset_groups, &mut scale_of, offset) {
                    Ok(x) => limits.push(x),
                    Err(mut e) => errors.append(&mut e),
                }
            }
            _ => {}
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    // S5.1: the sum per asset of what the limits authorise over a window.
    let mut ceiling_document: Vec<(String, u128)> = Vec::new();
    for l in &limits {
        let entry = ceiling_document.iter_mut().find(|(a, _)| *a == l.asset);
        let add = l.escalated_ceiling() as u128;
        match entry {
            Some((_, total)) => *total += add,
            None => ceiling_document.push((l.asset.clone(), add)),
        }
    }

    Ok(Compiled {
        charter_id: c.name.node.clone(),
        version: c.version,
        resolver_tier: c.resolver_tier.node.clone(),
        resolver_version: c.resolver_version,
        timezone_offset: offset,
        assets,
        asset_groups,
        instruments: c
            .decls
            .iter()
            .filter_map(|d| match d {
                Decl::Instrument(i) => Some(i.name.node.clone()),
                _ => None,
            })
            .collect(),
        prohibitions,
        limits,
        ceiling_document,
    })
}

fn compile_limit(
    l: &ast::LimitDecl,
    groups: &HashMap<&str, Vec<Atom>>,
    asset_groups: &[(String, Vec<String>)],
    scale_of: &mut impl FnMut(&str) -> Option<u8>,
    charter_offset: i32,
) -> Result<Limit, Vec<Diagnostic>> {
    let mut errors = Vec::new();

    let (dimension, asset, base) = match &l.dimension {
        ast::Dimension::Amount { base, .. } => {
            let a = base.node.asset.node.clone();
            let Some(dec) = scale_of(&a) else {
                return Err(vec![Diagnostic::error(
                    "E201",
                    format!("`{a}` does not resolve to a declared asset"),
                    base.span.clone(),
                )]);
            };
            match minor_units(&base.node, dec) {
                Ok(v) => (Dimension::Amount, a, v),
                Err(e) => return Err(vec![Diagnostic::error("E202", e, base.span.clone())]),
            }
        }
        ast::Dimension::Count { base, .. } => {
            (Dimension::Count, String::from("#count"), base.node)
        }
    };

    let mut exceptions = Vec::new();
    let excs = match &l.dimension {
        ast::Dimension::Amount { exceptions, .. } | ast::Dimension::Count { exceptions, .. } => {
            exceptions
        }
    };
    for e in excs {
        let sel = match selector(&e.condition, groups, asset_groups, charter_offset) {
            Ok(s) => s,
            Err(d) => {
                errors.push(d);
                continue;
            }
        };
        let v = match &e.value.node {
            ast::ExcValue::Money(m) => {
                let dec = scale_of(&m.asset.node).unwrap_or(0);
                match minor_units(m, dec) {
                    Ok(v) => ExcValue::Value(v),
                    Err(msg) => {
                        errors.push(Diagnostic::error("E202", msg, e.value.span.clone()));
                        continue;
                    }
                }
            }
            ast::ExcValue::Count(n) => ExcValue::Value(*n),
            // Without a parent chain to resolve against, `unlimited` compiles to the base:
            // finite, and never larger than what this level already permits. Resolving it
            // against the real parent belongs to the hierarchy pass (H4).
            ast::ExcValue::Unlimited => ExcValue::Unlimited(base),
        };
        exceptions.push((sel, v));
    }

    let applies = match &l.applies {
        Some(c) => match selector(c, groups, asset_groups, charter_offset) {
            Ok(s) => Some(s),
            Err(d) => {
                errors.push(d);
                None
            }
        },
        None => None,
    };

    let window = match &l.window.node {
        ast::Window::Rolling { seconds, .. } => Window::Rolling { seconds: *seconds as i64 },
        ast::Window::Fixed { unit, tz } => Window::Fixed {
            unit: CalUnit::parse(unit).unwrap_or(CalUnit::Day),
            // §5.4: a fixed window may override the charter offset for its own alignment only.
            offset: tz.as_deref().map(offset_seconds).unwrap_or(charter_offset),
        },
    };

    let scope = match l.scope.as_ref().map(|s| s.node) {
        None => Scope::None,
        Some(ast::Scope::Account) => Scope::Account,
        Some(ast::Scope::Agent) => Scope::Agent,
        Some(ast::Scope::Instrument) => Scope::Instrument,
        Some(ast::Scope::Counterparty) => Scope::Counterparty,
    };

    let mut escalations = Vec::new();
    for e in &l.escalations {
        let ceiling = match &e.ceiling.node {
            ast::ExcValue::Money(m) => {
                minor_units(m, scale_of(&m.asset.node).unwrap_or(0)).unwrap_or(0)
            }
            ast::ExcValue::Count(n) => *n,
            ast::ExcValue::Unlimited => base,
        };
        let trigger = match &e.trigger.node {
            ast::Trigger::Above(m) => {
                Trigger::Above(minor_units(m, scale_of(&m.asset.node).unwrap_or(0)).unwrap_or(0))
            }
            ast::Trigger::AtLeast(m) => {
                Trigger::AtLeast(minor_units(m, scale_of(&m.asset.node).unwrap_or(0)).unwrap_or(0))
            }
            ast::Trigger::AboveCount(n) => Trigger::Above(*n),
            ast::Trigger::AtLeastCount(n) => Trigger::AtLeast(*n),
            ast::Trigger::WhenExhausted => Trigger::WhenExhausted,
        };
        escalations.push(Escalation {
            trigger,
            quorum: e.quorum.node,
            approvers: e.approvers.node.clone(),
            ceiling,
            // §8.1.5: a default of one day where none is stated.
            within: e.within.as_ref().map(|w| w.node as i64).unwrap_or(86_400),
        });
    }

    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Limit {
        id: l.name.node.clone(),
        dimension,
        asset,
        base,
        exceptions,
        applies,
        window,
        scope,
        escalations,
    })
}

/// `value × 10^decimals`, exactly. A literal that cannot be represented exactly is an error,
/// never a rounding (E202).
fn minor_units(m: &ast::Money, decimals: u8) -> Result<u64, String> {
    if m.fraction.len() > decimals as usize {
        return Err(format!(
            "{}.{} has {} fractional digits but the asset has {decimals}; a literal that cannot \
             be represented exactly in minor units is an error, never a rounding",
            m.integer,
            m.fraction,
            m.fraction.len()
        ));
    }
    let mut padded = m.fraction.clone();
    while padded.len() < decimals as usize {
        padded.push('0');
    }
    let frac: u64 = if padded.is_empty() { 0 } else { padded.parse().map_err(|_| "overflow")? };
    let scale = 10u64.checked_pow(decimals as u32).ok_or("scale overflow")?;
    m.integer
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac))
        .ok_or_else(|| String::from("amount does not fit in u64 minor units (E203)"))
}

/// `UTC±HH:MM` to seconds. §2.9 already validated the shape and range.
fn offset_seconds(tz: &str) -> i32 {
    let Some(off) = tz.strip_prefix("UTC") else { return 0 };
    if off.len() != 6 {
        return 0;
    }
    let hh: i32 = off[1..3].parse().unwrap_or(0);
    let mm: i32 = off[4..6].parse().unwrap_or(0);
    let magnitude = hh * 3600 + mm * 60;
    if off.starts_with('-') {
        -magnitude
    } else {
        magnitude
    }
}

fn selector(
    c: &ast::Condition,
    groups: &HashMap<&str, Vec<Atom>>,
    asset_groups: &[(String, Vec<String>)],
    offset: i32,
) -> Result<Selector, Diagnostic> {
    Ok(match c {
        ast::Condition::And(a, b) => Selector::And(
            Box::new(selector(a, groups, asset_groups, offset)?),
            Box::new(selector(b, groups, asset_groups, offset)?),
        ),
        ast::Condition::Or(a, b) => Selector::Or(
            Box::new(selector(a, groups, asset_groups, offset)?),
            Box::new(selector(b, groups, asset_groups, offset)?),
        ),
        ast::Condition::Not(a) => {
            Selector::Not(Box::new(selector(a, groups, asset_groups, offset)?))
        }
        ast::Condition::Compare(cmp) => {
            let Some(field) = Field::parse(&cmp.field.node) else {
                return Err(Diagnostic::error(
                    "E301",
                    format!("`{}` is not a field in the closed set of §6", cmp.field.node),
                    cmp.field.span.clone(),
                ));
            };
            match cmp.operator.node.as_str() {
                "before" | "after" => {
                    let ast::Value::Date(d) = &cmp.value.node else {
                        return Err(Diagnostic::error(
                            "E301",
                            "`before` and `after` take a date literal",
                            cmp.value.span.clone(),
                        ));
                    };
                    let day = parse_date(d).ok_or_else(|| {
                        Diagnostic::error("E205", "not a real date", cmp.value.span.clone())
                    })?;
                    if cmp.operator.node == "before" {
                        Selector::Before { date: day }
                    } else {
                        Selector::After { date: day }
                    }
                }
                "is at least" => {
                    let ast::Value::Plane(p) = &cmp.value.node else {
                        return Err(Diagnostic::error(
                            "E301",
                            "`is at least` compares on the provenance order",
                            cmp.value.span.clone(),
                        ));
                    };
                    Selector::IsAtLeast {
                        field,
                        plane: Plane::parse(p).unwrap_or(Plane::Network),
                    }
                }
                op => {
                    let negated = op == "is not" || op == "not in";
                    let values = atoms(&cmp.value.node, groups, asset_groups);
                    Selector::Is { field, values, negated }
                }
            }
        }
    })
}

/// Expand a value into resolved atoms. Group and asset-group names are dereferenced here so
/// evaluation never has to.
fn atoms(
    v: &ast::Value,
    groups: &HashMap<&str, Vec<Atom>>,
    asset_groups: &[(String, Vec<String>)],
) -> Vec<Atom> {
    match v {
        ast::Value::Named(n) => {
            if let Some(members) = groups.get(n.as_str()) {
                return members.clone();
            }
            if let Some((_, members)) = asset_groups.iter().find(|(g, _)| g == n) {
                return members.iter().map(|m| Atom::Text(m.clone())).collect();
            }
            vec![Atom::Text(n.clone())]
        }
        ast::Value::Literal(l) => vec![Atom::Text(l.to_string())],
        ast::Value::Plane(p) => {
            vec![Atom::Plane(Plane::parse(p).unwrap_or(Plane::Network))]
        }
        ast::Value::Date(d) => vec![Atom::Text(d.clone())],
        ast::Value::Set(items) => {
            items.iter().flat_map(|i| atoms(&i.node, groups, asset_groups)).collect()
        }
    }
}

fn parse_date(s: &str) -> Option<i32> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let y: i64 = s[0..4].parse().ok()?;
    let m: i64 = s[5..7].parse().ok()?;
    let d: i64 = s[8..10].parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let days = days_from_civil(y, m, d);
    // Reject 2026-02-30 and friends: a real date survives the round trip.
    if pays_policy::calendar::civil_from_days(days) != (y, m, d) {
        return None;
    }
    Some(days as i32)
}
