//! The static rules, S1–S28.
//!
//! Every rule carries its number so a conformance case can name what it tests, and every
//! diagnostic carries the stable code from §10 so two implementations report the same thing.
//!
//! Rules that need the resolver — S7 through S13, and the minor-unit checks in §2.6 — are
//! marked and left to a later pass rather than approximated here. An approximate S7 is worse
//! than an absent one: it would pass documents the engine must refuse.

use crate::ast::*;
use crate::diag::Diagnostic;
use crate::lex::Span;
use std::collections::HashMap;

pub fn check(c: &Charter) -> Vec<Diagnostic> {
    let mut d = Vec::new();
    let table = build_table(c, &mut d);
    s21_s28_names(c, &table, &mut d);
    s_type_table(c, &table, &mut d);
    s19_s20_asset_names(c, &mut d);
    s22_asset_groups(c, &table, &mut d);
    s26_s27_instruments(c, &mut d);
    s16_at_least_one_limit(c, &mut d);
    s14_s15_s17_escalations(c, &table, &mut d);
    s6_one_asset_per_limit(c, &mut d);
    s4_exceptions_disjoint(c, &mut d);
    s18_prohibitions_reachable(c, &mut d);
    e314_unlimited_in_root(c, &mut d);
    w3_unused_assets(c, &table, &mut d);
    d
}

struct Entry {
    kind: Kind,
    span: Span,
}

/// §5.1: one flat namespace per document. Redeclaring a name is E210, including across kinds.
fn build_table(c: &Charter, d: &mut Vec<Diagnostic>) -> HashMap<String, Entry> {
    let mut t: HashMap<String, Entry> = HashMap::new();
    for decl in &c.decls {
        let n = decl.name();
        if let Some(prev) = t.get(&n.node) {
            d.push(
                Diagnostic::error(
                    "E210",
                    format!("`{}` is already declared as {}", n.node, prev.kind.describe()),
                    n.span.clone(),
                )
                .with_related(prev.span.clone(), "first declared here"),
            );
            continue;
        }
        t.insert(n.node.clone(), Entry { kind: decl.kind(), span: n.span.clone() });
    }
    t
}

/// The kind a field's value position requires (§7.1.1's table).
fn kind_for_field(field: &str) -> Option<Kind> {
    match field {
        "asset" => Some(Kind::Asset),
        "instrument" => Some(Kind::Instrument),
        "counterparty" | "merchant.category" | "merchant.country" => Some(Kind::Group),
        _ => None,
    }
}

/// S21 (every asset and instrument named is declared here) and S28 (the declaration's kind
/// matches the position). There is no position where two kinds are both acceptable.
fn s21_s28_names(c: &Charter, t: &HashMap<String, Entry>, d: &mut Vec<Diagnostic>) {
    let mut want = |name: &str, span: &Span, kinds: &[Kind], code: &'static str, what: &str, d: &mut Vec<Diagnostic>| {
        match t.get(name) {
            None => d.push(Diagnostic::error(
                code,
                format!(
                    "`{name}` is not declared in this document. The resolver is not a namespace \
                     and a parent charter does not export declarations (S21)."
                ),
                span.clone(),
            )),
            Some(e) if !kinds.contains(&e.kind) => d.push(
                Diagnostic::error(
                    code,
                    format!("{what} is required here; `{name}` is {}", e.kind.describe()),
                    span.clone(),
                )
                .with_related(e.span.clone(), "declared here"),
            ),
            _ => {}
        }
    };

    const ASSETISH: &[Kind] = &[Kind::Asset, Kind::AssetGroup];

    for decl in &c.decls {
        match decl {
            Decl::Limit(l) => {
                for m in monies(l) {
                    want(&m.asset.node, &m.asset.span, ASSETISH, "E201", "an asset", d);
                }
                for e in &l.escalations {
                    want(
                        &e.approvers.node,
                        &e.approvers.span,
                        &[Kind::Approvers],
                        "E308",
                        "an approver set",
                        d,
                    );
                }
                if let Some(a) = &l.applies {
                    check_condition(a, t, &mut want, d);
                }
                for ex in exceptions(l) {
                    check_condition(&ex.condition, t, &mut want, d);
                }
            }
            Decl::Prohibit(p) => check_condition(&p.condition, t, &mut want, d),
            Decl::AssetGroup(g) => {
                for m in &g.members {
                    want(&m.node, &m.span, &[Kind::Asset], "E216", "an asset", d);
                }
            }
            _ => {}
        }
    }
}

fn check_condition<F>(cond: &Condition, t: &HashMap<String, Entry>, want: &mut F, d: &mut Vec<Diagnostic>)
where
    F: FnMut(&str, &Span, &[Kind], &'static str, &str, &mut Vec<Diagnostic>),
{
    match cond {
        Condition::Or(a, b) | Condition::And(a, b) => {
            check_condition(a, t, want, d);
            check_condition(b, t, want, d);
        }
        Condition::Not(a) => check_condition(a, t, want, d),
        Condition::Compare(cmp) => {
            let Some(kind) = kind_for_field(&cmp.field.node) else { return };
            let (code, what) = match kind {
                Kind::Asset => ("E201", "an asset"),
                Kind::Instrument => ("E217", "an instrument"),
                _ => ("E303", "a group"),
            };
            let kinds: &[Kind] = match kind {
                Kind::Asset => &[Kind::Asset, Kind::AssetGroup],
                k => core::slice::from_ref(Box::leak(Box::new(k))),
            };
            let mut visit = |v: &Spanned<Value>, d: &mut Vec<Diagnostic>| {
                if let Value::Named(n) = &v.node {
                    want(n, &v.span, kinds, code, what, d);
                }
            };
            match &cmp.value.node {
                Value::Set(items) => {
                    for it in items {
                        visit(it, d);
                    }
                }
                _ => visit(&cmp.value, d),
            }
        }
    }
}

fn monies(l: &LimitDecl) -> Vec<Money> {
    let mut v = Vec::new();
    if let Dimension::Amount { base, exceptions } = &l.dimension {
        v.push(base.node.clone());
        for e in exceptions {
            if let ExcValue::Money(m) = &e.value.node {
                v.push(m.clone());
            }
        }
    }
    for e in &l.escalations {
        match &e.trigger.node {
            Trigger::Above(m) | Trigger::AtLeast(m) => v.push(m.clone()),
            _ => {}
        }
        if let ExcValue::Money(m) = &e.ceiling.node {
            v.push(m.clone());
        }
    }
    v
}

fn exceptions(l: &LimitDecl) -> &[Exception] {
    match &l.dimension {
        Dimension::Amount { exceptions, .. } | Dimension::Count { exceptions, .. } => exceptions,
    }
}

/// S19: an alias MUST begin with the symbol it binds. S20: it MUST NOT be the bare symbol.
/// S20.1: an asset group's name ends `_group` and an asset's does not.
fn s19_s20_asset_names(c: &Charter, d: &mut Vec<Diagnostic>) {
    for decl in &c.decls {
        if let Decl::Asset(a) = decl {
            let sym = a.reference.node.symbol();
            let name = &a.name.node;
            // A CAIP-19 reference has no author-stated symbol to check against; S7 fills it
            // from the resolver, so S19 is deferred to that pass for this form only.
            if !sym.is_empty() {
                if name == sym {
                    d.push(Diagnostic::error(
                        "E212",
                        format!(
                            "`{name}` is the bare symbol. An alias must carry a qualifier — \
                             `{sym}_circle`, `{sym}_wormhole` — so a reader cannot think \
                             \"this is {sym}\" without thinking \"which {sym}\" (S20)."
                        ),
                        a.name.span.clone(),
                    ));
                } else if !name.strip_prefix(sym).is_some_and(|r| r.starts_with('_')) {
                    d.push(
                        Diagnostic::error(
                            "E211",
                            format!(
                                "`{name}` does not name what it binds: this reference's symbol \
                                 is `{sym}`, so the alias must begin `{sym}_` (S19)."
                            ),
                            a.name.span.clone(),
                        )
                        .with_related(a.reference.span.clone(), "bound here"),
                    );
                }
            }
            if name.ends_with("_group") {
                d.push(Diagnostic::error(
                    "E222",
                    format!("`{name}` is a single asset and must not end `_group` (S20.1)"),
                    a.name.span.clone(),
                ));
            }
        }
        if let Decl::AssetGroup(g) = decl {
            if !g.name.node.ends_with("_group") {
                d.push(Diagnostic::error(
                    "E222",
                    format!(
                        "`{}` is an asset group and must end `_group` (S20.1). At a use site, \
                         `amount 100.00 {}` is a cap on one chain or across all of them, and \
                         nothing else discloses which.",
                        g.name.node, g.name.node
                    ),
                    g.name.span.clone(),
                ));
            }
        }
    }
}

/// S22: every member of an asset group is the same asset.
fn s22_asset_groups(c: &Charter, t: &HashMap<String, Entry>, d: &mut Vec<Diagnostic>) {
    let assets: HashMap<&str, &AssetDecl> = c
        .decls
        .iter()
        .filter_map(|x| match x {
            Decl::Asset(a) => Some((a.name.node.as_str(), a)),
            _ => None,
        })
        .collect();

    for decl in &c.decls {
        let Decl::AssetGroup(g) = decl else { continue };

        if g.members.len() < 2 {
            d.push(Diagnostic::error(
                "E215",
                format!(
                    "`{}` has {} member(s); a group of one is an alias wearing a second name (S22)",
                    g.name.node,
                    g.members.len()
                ),
                g.name.span.clone(),
            ));
        }

        let mut seen: HashMap<&str, &Span> = HashMap::new();
        for m in &g.members {
            if let Some(prev) = seen.get(m.node.as_str()) {
                d.push(
                    Diagnostic::error(
                        "E214",
                        format!("`{}` appears twice in this group (S22)", m.node),
                        m.span.clone(),
                    )
                    .with_related((*prev).clone(), "first listed here"),
                );
            } else {
                seen.insert(&m.node, &m.span);
            }
        }

        // Nested groups are E216, which S28's kind check already reports; skip them here so
        // one mistake produces one diagnostic.
        let mut first: Option<(&str, &str, &Span)> = None;
        for m in &g.members {
            if t.get(&m.node).map(|e| e.kind) != Some(Kind::Asset) {
                continue;
            }
            let Some(a) = assets.get(m.node.as_str()) else { continue };
            let (sym, iss) = (a.reference.node.symbol(), a.reference.node.issuer());
            match first {
                None => first = Some((sym, iss, &m.span)),
                Some((fsym, fiss, fspan)) => {
                    if sym != fsym || iss != fiss {
                        d.push(
                            Diagnostic::error(
                                "E213",
                                format!(
                                    "`{}` is {sym}/{iss}, but this group's first member is \
                                     {fsym}/{fiss}. Members must be one asset — same symbol, \
                                     same issuer, same decimals (S22). Bridged tokens are a \
                                     different credit risk that shares a ticker.",
                                    m.node
                                ),
                                m.span.clone(),
                            )
                            .with_related(fspan.clone(), "first member"),
                        );
                    }
                }
            }
        }
    }
}

/// S26: no credential in an instrument reference. S27: the name matches the network.
fn s26_s27_instruments(c: &Charter, d: &mut Vec<Diagnostic>) {
    for decl in &c.decls {
        let Decl::Instrument(i) = decl else { continue };
        let prefix = i.reference.node.prefix();
        let name = &i.name.node;

        if name == prefix {
            d.push(Diagnostic::error(
                "E212",
                format!("`{name}` is the bare network; an instrument name needs a qualifier (S27)"),
                i.name.span.clone(),
            ));
        } else if !name.strip_prefix(prefix).is_some_and(|r| r.starts_with('_')) {
            d.push(
                Diagnostic::error(
                    "E211",
                    format!(
                        "`{name}` does not name what it binds: this reference is `{prefix}`, so \
                         the name must begin `{prefix}_` (S27)."
                    ),
                    i.name.span.clone(),
                )
                .with_related(i.reference.span.clone(), "bound here"),
            );
        }

        // A compiler SHOULD reject a handle that looks like a PAN: that case is both the most
        // likely and the most damaging, and catching it cheaply beats catching nothing.
        let h = i.reference.node.handle();
        if looks_like_a_pan(h) {
            d.push(Diagnostic::error(
                "E220",
                "this handle is a 13-19 digit number passing Luhn, which is a card number. A \
                 charter is reviewed, diffed, signed and handed to an auditor; the handle \
                 identifies which instrument and must never be able to charge it (S26)."
                    .to_string(),
                i.reference.span.clone(),
            ));
        }
    }
}

fn looks_like_a_pan(s: &str) -> bool {
    if !(13..=19).contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0u32;
    for (i, b) in s.bytes().rev().enumerate() {
        let mut v = (b - b'0') as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

/// S16: a document MUST declare at least one limit. Prohibitions do not satisfy it — a
/// document of pure prohibitions permits everything it did not think to forbid.
fn s16_at_least_one_limit(c: &Charter, d: &mut Vec<Diagnostic>) {
    if c.decls.iter().any(|x| matches!(x, Decl::Limit(_))) {
        return;
    }
    let has_prohibitions = c.decls.iter().any(|x| matches!(x, Decl::Prohibit(_)));
    let (code, msg): (&'static str, String) = if has_prohibitions {
        (
            "E316",
            "this document declares prohibitions and no limit. A deny-list permits everything \
             it did not think to forbid, which is the posture this language refuses (S16)."
                .into(),
        )
    } else {
        (
            "E311",
            "no limits declared. An empty charter is more likely a truncated file than an \
             intent to permit everything, and permitting everything must be impossible to \
             express by omission (S16)."
                .into(),
        )
    };
    d.push(Diagnostic::error(code, msg, c.name.span.clone()));
}

/// S14 (the approver set and quorum), S15 and S17 (one escalation per trigger kind, where
/// `above` and `at least` are one kind), S5 (the ceiling is a literal at or above the base).
fn s14_s15_s17_escalations(c: &Charter, t: &HashMap<String, Entry>, d: &mut Vec<Diagnostic>) {
    for decl in &c.decls {
        let Decl::Limit(l) = decl else { continue };
        let mut seen: HashMap<&'static str, Span> = HashMap::new();
        for e in &l.escalations {
            let kind = e.trigger.node.kind();
            if let Some(prev) = seen.get(kind) {
                let extra = if kind == "threshold" {
                    " `above` and `at least` are the same trigger kind: two thresholds meeting \
                     at a boundary have no defined composition on it (S17)."
                } else {
                    ""
                };
                d.push(
                    Diagnostic::error(
                        "E310",
                        format!("`{}` already has a {kind} escalation.{extra}", l.name.node),
                        e.trigger.span.clone(),
                    )
                    .with_related(prev.clone(), "the other one"),
                );
            } else {
                seen.insert(kind, e.trigger.span.clone());
            }

            if let Some(entry) = t.get(&e.approvers.node) {
                if entry.kind == Kind::Approvers {
                    let size = c
                        .decls
                        .iter()
                        .find_map(|x| match x {
                            Decl::Approvers(a) if a.name.node == e.approvers.node => {
                                Some(a.members.len() as u64)
                            }
                            _ => None,
                        })
                        .unwrap_or(0);
                    if e.quorum.node < 1 || e.quorum.node > size {
                        d.push(Diagnostic::error(
                            "E309",
                            format!(
                                "a quorum of {} over `{}`, which has {size} member(s) (S14)",
                                e.quorum.node, e.approvers.node
                            ),
                            e.quorum.span.clone(),
                        ));
                    }
                }
            }

            // S5: the escalation ceiling must be at or above the base, or it is dead text.
            if let (ExcValue::Money(ceil), Dimension::Amount { base, .. }) =
                (&e.ceiling.node, &l.dimension)
            {
                if let (Some(cm), Some(bm)) = (minor_units(ceil), minor_units(&base.node)) {
                    if cm < bm {
                        d.push(Diagnostic::error(
                            "E306",
                            format!(
                                "this escalation's ceiling is below `{}`'s own base, so the \
                                 escalated path authorises less than the autonomous one (S5)",
                                l.name.node
                            ),
                            e.ceiling.span.clone(),
                        ));
                    }
                }
            }
        }
    }
}

/// Comparable only against another literal of the same asset; the resolver supplies the true
/// scale, so this is a same-scale comparison and nothing more.
fn minor_units(m: &Money) -> Option<u128> {
    let frac: u128 = if m.fraction.is_empty() { 0 } else { m.fraction.parse().ok()? };
    let scale = 10u128.checked_pow(m.fraction.len() as u32)?;
    Some((m.integer as u128).checked_mul(scale)? + frac)
}

/// S6: every money literal in one limit names the same asset.
fn s6_one_asset_per_limit(c: &Charter, d: &mut Vec<Diagnostic>) {
    for decl in &c.decls {
        let Decl::Limit(l) = decl else { continue };
        let ms = monies(l);
        let Some(first) = ms.first() else { continue };
        for m in ms.iter().skip(1) {
            if m.asset.node != first.asset.node {
                d.push(
                    Diagnostic::error(
                        "E307",
                        format!(
                            "`{}` mixes `{}` and `{}`. A cap without one asset is not a bound, \
                             because summing across assets sums incommensurable units (S6).",
                            l.name.node, first.asset.node, m.asset.node
                        ),
                        m.asset.span.clone(),
                    )
                    .with_related(first.asset.span.clone(), "the limit's asset"),
                );
            }
        }
    }
}

/// S18: a prohibition MUST be reachable. Every other construct fails towards refusing; a
/// prohibition that silently never fires fails towards permitting, and looks exactly like
/// protection while providing none.
fn s18_prohibitions_reachable(c: &Charter, d: &mut Vec<Diagnostic>) {
    for decl in &c.decls {
        let Decl::Prohibit(p) = decl else { continue };
        if let Some(why) = unsatisfiable(&p.condition) {
            d.push(Diagnostic::error(
                "E317",
                format!("`{}` can never hold: {why} (S18)", p.name.node),
                p.name.span.clone(),
            ));
        }
    }
}

/// Deliberately conservative. It proves unsatisfiability for the shapes that actually occur
/// and says nothing about the rest — a false "unreachable" would reject a working charter.
fn unsatisfiable(c: &Condition) -> Option<String> {
    match c {
        Condition::And(a, b) => {
            if let (Condition::Compare(x), Condition::Compare(y)) = (&**a, &**b) {
                // `date after L and date before R` with an empty span.
                if x.field.node == "date" && y.field.node == "date" {
                    if let (Value::Date(l), Value::Date(r)) = (&x.value.node, &y.value.node) {
                        let (after, before) = match (x.operator.node.as_str(), y.operator.node.as_str())
                        {
                            ("after", "before") => (l, r),
                            ("before", "after") => (r, l),
                            _ => return None,
                        };
                        if after >= before {
                            return Some(format!(
                                "the range after {after} and before {before} contains no day"
                            ));
                        }
                    }
                }
            }
            // `X and not X`.
            if let (Condition::Compare(x), Condition::Not(inner)) = (&**a, &**b) {
                if let Condition::Compare(y) = &**inner {
                    if same_comparison(x, y) {
                        return Some(format!(
                            "`{} {} …` is conjoined with its own negation",
                            x.field.node, x.operator.node
                        ));
                    }
                }
            }
            unsatisfiable(a).or_else(|| unsatisfiable(b))
        }
        _ => None,
    }
}

fn same_comparison(a: &Comparison, b: &Comparison) -> bool {
    a.field.node == b.field.node
        && a.operator.node == b.operator.node
        && format!("{:?}", a.value.node) == format!("{:?}", b.value.node)
}

/// E314: `unlimited` means "this level adds no constraint", which is finite only when a
/// parent supplies one.
fn e314_unlimited_in_root(c: &Charter, d: &mut Vec<Diagnostic>) {
    if c.extends.is_some() {
        return;
    }
    for decl in &c.decls {
        let Decl::Limit(l) = decl else { continue };
        for e in exceptions(l) {
            if matches!(e.value.node, ExcValue::Unlimited) {
                d.push(Diagnostic::error(
                    "E314",
                    "`unlimited` is legal only in a charter that extends another, where it \
                     resolves to the parent's ceiling. This charter extends nothing, so the \
                     ceiling would be unbounded and S5 fails."
                        .to_string(),
                    e.value.span.clone(),
                ));
            }
        }
    }
}

/// W3: an unused asset still enters `resolved_assets`, so a later change to something this
/// charter never spends becomes a compile failure for a charter it does not affect.
fn w3_unused_assets(c: &Charter, _t: &HashMap<String, Entry>, d: &mut Vec<Diagnostic>) {
    let mut used: Vec<&str> = Vec::new();
    for decl in &c.decls {
        match decl {
            Decl::Limit(l) => {
                for m in monies(l) {
                    used.push(Box::leak(m.asset.node.clone().into_boxed_str()));
                }
            }
            Decl::AssetGroup(g) => {
                for m in &g.members {
                    used.push(&m.node);
                }
            }
            _ => {}
        }
    }
    for decl in &c.decls {
        let (name, span) = match decl {
            Decl::Asset(a) => (&a.name.node, &a.name.span),
            _ => continue,
        };
        if !used.iter().any(|u| *u == name.as_str()) {
            d.push(Diagnostic::warning(
                "W3",
                format!("`{name}` is declared and never used (W3)"),
                span.clone(),
            ));
        }
    }
}

/// §6's type table: each field admits a fixed set of operators and value shapes, and anything
/// else is a type error (E301). The tag of a literal must match the field too (E303).
///
/// The table is the enumeration itself rather than a set of special cases, so adding a field
/// means adding a row and nothing else — which is what keeps the vocabulary closed (S2).
fn field_row(field: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    // (operators, permitted value shapes)
    const SET: &[&str] = &["is", "is not", "in", "not in"];
    const SET_ORDERED: &[&str] = &["is", "is not", "in", "not in", "is at least"];
    const DATE_OPS: &[&str] = &["before", "after"];
    Some(match field {
        "counterparty" => (SET, &["address", "group"]),
        "asset" => (SET, &["asset", "asset_group"]),
        "asset.class" => (SET, &["class"]),
        "instrument" => (SET, &["instrument"]),
        "merchant.category" => (SET, &["mcc", "group"]),
        "merchant.country" => (SET, &["country", "group"]),
        "provenance"
        | "provenance.recipient"
        | "provenance.amount"
        | "provenance.asset"
        | "provenance.venue" => (SET_ORDERED, &["plane"]),
        "date" => (DATE_OPS, &["date"]),
        _ => return None,
    })
}

/// §6 and §2.11, over every condition in the document.
fn s_type_table(c: &Charter, t: &HashMap<String, Entry>, d: &mut Vec<Diagnostic>) {
    let mut visit = |cond: &Condition, d: &mut Vec<Diagnostic>| walk(cond, t, d);
    for decl in &c.decls {
        match decl {
            Decl::Prohibit(p) => visit(&p.condition, d),
            Decl::Limit(l) => {
                if let Some(a) = &l.applies {
                    visit(a, d);
                }
                for e in exceptions(l) {
                    visit(&e.condition, d);
                }
            }
            _ => {}
        }
    }
}

fn walk(c: &Condition, t: &HashMap<String, Entry>, d: &mut Vec<Diagnostic>) {
    match c {
        Condition::And(a, b) | Condition::Or(a, b) => {
            walk(a, t, d);
            walk(b, t, d);
        }
        Condition::Not(a) => walk(a, t, d),
        Condition::Compare(cmp) => {
            let Some((ops, shapes)) = field_row(&cmp.field.node) else {
                d.push(Diagnostic::error(
                    "E301",
                    format!(
                        "`{}` is not a field. §6's set is closed, and adding one is an engine \
                         change under review rather than something an author can do (S2).",
                        cmp.field.node
                    ),
                    cmp.field.span.clone(),
                ));
                return;
            };
            if !ops.contains(&cmp.operator.node.as_str()) {
                d.push(Diagnostic::error(
                    "E301",
                    format!(
                        "`{}` does not take `{}`; it takes {}.",
                        cmp.field.node,
                        cmp.operator.node,
                        ops.join(", ")
                    ),
                    cmp.operator.span.clone(),
                ));
                return;
            }
            // `is`/`is not` take one value; `in`/`not in` take a group or an inline set.
            let is_membership = matches!(cmp.operator.node.as_str(), "in" | "not in");
            if is_membership && !matches!(cmp.value.node, Value::Set(_) | Value::Named(_)) {
                d.push(Diagnostic::error(
                    "E301",
                    format!("`{}` takes a group or an inline set", cmp.operator.node),
                    cmp.value.span.clone(),
                ));
                return;
            }
            check_shape(&cmp.value, &cmp.field.node, shapes, t, d);
        }
    }
}

fn check_shape(
    v: &Spanned<Value>,
    field: &str,
    shapes: &[&str],
    t: &HashMap<String, Entry>,
    d: &mut Vec<Diagnostic>,
) {
    match &v.node {
        Value::Set(items) => {
            for i in items {
                check_shape(i, field, shapes, t, d);
            }
        }
        Value::Plane(_) => require(shapes, "plane", field, "a provenance plane", &v.span, d),
        Value::Date(_) => require(shapes, "date", field, "a date", &v.span, d),
        Value::Literal(Literal::Address(_)) => {
            require(shapes, "address", field, "an address", &v.span, d)
        }
        Value::Literal(Literal::Tagged(tag, _)) => {
            if !shapes.contains(&tag.as_str()) {
                d.push(Diagnostic::error(
                    "E303",
                    format!(
                        "`{field}` does not take a `{tag}:` literal. Each tag belongs to exactly \
                         one field: mcc to merchant.category, country to merchant.country, class \
                         to asset.class (§2.11)."
                    ),
                    v.span.clone(),
                ));
            }
        }
        Value::Named(n) => {
            // A name's kind is checked by S28; here only whether a *group* is admissible at
            // all for this field, so the two rules do not report the same mistake twice.
            let kind = t.get(n).map(|e| e.kind);
            if kind == Some(Kind::Group) && !shapes.contains(&"group") {
                d.push(Diagnostic::error(
                    "E303",
                    format!("`{field}` does not take a group"),
                    v.span.clone(),
                ));
            }
        }
    }
}

fn require(
    shapes: &[&str],
    shape: &str,
    field: &str,
    described: &str,
    span: &Span,
    d: &mut Vec<Diagnostic>,
) {
    if !shapes.contains(&shape) {
        d.push(Diagnostic::error(
            "E301",
            format!("`{field}` does not take {described}"),
            span.clone(),
        ));
    }
}

/// S4 · Exceptions within one dimension MUST be provably disjoint (E304).
///
/// The burden runs the way the spec states it: a pair is rejected unless disjointness can be
/// **proved**, not accepted unless overlap can be. "Any pair a compiler cannot separate" is
/// rejected, so a conservative prover is the safe kind here — the failure mode of not proving
/// enough is a document an author must rewrite, and the failure mode of the opposite is a
/// ceiling resolved at runtime by whichever clause was reached first.
///
/// > Forcing disjointness rather than resolving by priority is the strict choice, and it is
/// > reversible: a later version can relax it without invalidating any charter written under
/// > it, whereas the reverse breaks documents already deployed.
///
/// Prohibitions are exempt in both directions (§7 S4), and are not considered here.
fn s4_exceptions_disjoint(c: &Charter, d: &mut Vec<Diagnostic>) {
    let groups: HashMap<&str, Vec<String>> = c
        .decls
        .iter()
        .filter_map(|x| match x {
            Decl::Group(g) => {
                Some((g.name.node.as_str(), g.members.iter().map(|m| m.node.to_string()).collect()))
            }
            _ => None,
        })
        .collect();

    for decl in &c.decls {
        let Decl::Limit(l) = decl else { continue };
        let excs = exceptions(l);
        for i in 0..excs.len() {
            for j in (i + 1)..excs.len() {
                if disjoint(&excs[i].condition, &excs[j].condition, &groups) {
                    continue;
                }
                d.push(
                    Diagnostic::error(
                        "E304",
                        format!(
                            "these two exceptions of `{}` are not provably disjoint. S4 rejects \
                             a pair a compiler cannot separate rather than resolving it by \
                             priority: a ceiling settled by declaration order is one a reviewer \
                             has to simulate, and an author who wrote two clauses believing them \
                             exclusive would be paid by whichever the parser reached first.",
                            l.name.node
                        ),
                        excs[j].value.span.clone(),
                    )
                    .with_related(excs[i].value.span.clone(), "the other one"),
                );
            }
        }
    }
}

/// Can these two conditions be proved never to hold together?
///
/// Only the shapes that actually occur are proved. Everything else is "not proved", which S4
/// turns into E304.
fn disjoint(a: &Condition, b: &Condition, groups: &HashMap<&str, Vec<String>>) -> bool {
    let (Condition::Compare(x), Condition::Compare(y)) = (a, b) else {
        // A conjunction is disjoint from something if *either* conjunct is: `X and Y` cannot
        // hold when X cannot.
        return match (a, b) {
            (Condition::And(p, q), other) | (other, Condition::And(p, q)) => {
                disjoint(p, other, groups) || disjoint(q, other, groups)
            }
            _ => false,
        };
    };
    if x.field.node != y.field.node {
        // Different fields say nothing about each other: `counterparty is A` and
        // `merchant.category is B` can both hold.
        return false;
    }

    match (x.operator.node.as_str(), y.operator.node.as_str()) {
        // Two positive membership tests over disjoint value sets cannot both hold.
        ("is" | "in", "is" | "in") => match (members(&x.value.node, groups), members(&y.value.node, groups)) {
            (Some(p), Some(q)) => !p.iter().any(|m| q.contains(m)),
            _ => false,
        },
        // Non-overlapping date ranges. `before L` and `after R` are disjoint when L <= R.
        ("before", "after") => match (&x.value.node, &y.value.node) {
            (Value::Date(l), Value::Date(r)) => l <= r,
            _ => false,
        },
        ("after", "before") => match (&x.value.node, &y.value.node) {
            (Value::Date(r), Value::Date(l)) => l <= r,
            _ => false,
        },
        _ => false,
    }
}

/// The values a comparison can match, with group names expanded. `None` where the shape is
/// one this prover does not model, which S4 then treats as not-disjoint.
fn members(v: &Value, groups: &HashMap<&str, Vec<String>>) -> Option<Vec<String>> {
    match v {
        Value::Literal(l) => Some(vec![l.to_string()]),
        Value::Plane(p) => Some(vec![p.clone()]),
        Value::Date(d) => Some(vec![d.clone()]),
        // An undeclared name is its own singleton: S21 reports it, and inventing an expansion
        // here would make one mistake produce two diagnostics.
        Value::Named(n) => Some(groups.get(n.as_str()).cloned().unwrap_or_else(|| vec![n.clone()])),
        Value::Set(items) => {
            let mut out = Vec::new();
            for i in items {
                out.extend(members(&i.node, groups)?);
            }
            Some(out)
        }
    }
}
