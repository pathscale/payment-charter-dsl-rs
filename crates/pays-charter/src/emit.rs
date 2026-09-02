//! AST to the canonical text form (§1.2).
//!
//! The counterpart of `payment-charter-dsl-ts`'s emitter, and it must agree with it byte for
//! byte. Two implementations of one canonical form drift unless something compares them; here
//! that something is `roundtrip/`, where parsing this output must reproduce this output.
//!
//! Canonicality constrains output only. A parser accepts any conforming document, canonical or
//! not (§2.1), and this decides what it emits.

use crate::ast::*;

/// Emit the canonical text form. Always ends with exactly one `\n`.
pub fn emit(c: &Charter) -> String {
    let mut out: Vec<String> = Vec::new();

    // Header: grammar order, one per line, unindented, no blank line between.
    out.push(format!("charter {} version {}", c.name.node, c.version));
    if let Some((parent, v)) = &c.extends {
        out.push(format!("extends {}@{}", parent.node, v));
    }
    out.push(format!("resolver {}@{}", c.resolver_tier.node, c.resolver_version));
    out.push(format!("timezone {}", c.timezone.node));
    out.push(String::new());

    // Grouped by kind, sorted by identifier within each kind. Declaration order is not
    // semantic (§5.2), so sorting makes the output a function of the meaning rather than of
    // the author's typing.
    const ORDER: [Kind; 7] = [
        Kind::Asset,
        Kind::AssetGroup,
        Kind::Instrument,
        Kind::Group,
        Kind::Approvers,
        Kind::Prohibit,
        Kind::Limit,
    ];

    let mut first_group = true;
    for kind in ORDER {
        let mut group: Vec<&Decl> = c.decls.iter().filter(|d| d.kind() == kind).collect();
        group.sort_by(|a, b| a.name().node.cmp(&b.name().node));
        if group.is_empty() {
            continue;
        }
        if !first_group {
            out.push(String::new());
        }
        first_group = false;

        for (i, d) in group.iter().enumerate() {
            // A blank line separates each limit and each prohibition from the next;
            // consecutive asset, asset group, instrument, group and approvers declarations are
            // not separated.
            if i > 0 && matches!(kind, Kind::Limit | Kind::Prohibit) {
                out.push(String::new());
            }
            out.extend(declaration(d));
        }
    }

    let body: Vec<String> = out.iter().map(|l| l.trim_end().to_string()).collect();
    let mut s = body.join("\n");
    while s.ends_with('\n') {
        s.pop();
    }
    s.push('\n');
    s
}

fn declaration(d: &Decl) -> Vec<String> {
    match d {
        // One space either side of `=`, and no alignment padding: alignment depends on the
        // widest name in the block, so it rewrites unrelated lines when a name changes.
        Decl::Asset(a) => vec![format!("  asset {} = {}", a.name.node, a.reference.node)],
        Decl::AssetGroup(g) => {
            let members: Vec<&str> = g.members.iter().map(|m| m.node.as_str()).collect();
            vec![format!("  asset group {} = {}", g.name.node, set(&members))]
        }
        Decl::Instrument(i) => {
            vec![format!("  instrument {} = {}", i.name.node, i.reference.node)]
        }
        Decl::Group(g) => {
            let members: Vec<String> = g.members.iter().map(|m| m.node.to_string()).collect();
            let refs: Vec<&str> = members.iter().map(|s| s.as_str()).collect();
            vec![format!("  group {} = {}", g.name.node, set(&refs))]
        }
        Decl::Approvers(a) => {
            let members: Vec<&str> = a.members.iter().map(|m| m.node.as_str()).collect();
            vec![format!("  approvers {} = {}", a.name.node, set(&members))]
        }
        Decl::Prohibit(p) => {
            vec![format!("  prohibit {} when {}", p.name.node, condition(&p.condition, 0))]
        }
        Decl::Limit(l) => limit(l),
    }
}

fn limit(l: &LimitDecl) -> Vec<String> {
    let mut out = vec![format!("  limit {}", l.name.node)];

    // Clauses in grammar order: dimension, its exceptions, `for`, `per`, `scope`, `escalate`.
    let exceptions = match &l.dimension {
        Dimension::Amount { base, exceptions } => {
            out.push(format!("    amount {}", money(&base.node)));
            exceptions
        }
        Dimension::Count { base, exceptions } => {
            out.push(format!("    count {}", base.node));
            exceptions
        }
    };

    // Sorted ascending by byte value of the emitted text. S4 forces them disjoint, so their
    // order carries no meaning.
    let mut lines: Vec<String> = exceptions
        .iter()
        .map(|e| format!("except {} when {}", exc_value(&e.value.node), condition(&e.condition, 0)))
        .collect();
    lines.sort();
    for e in lines {
        out.push(format!("      {e}"));
    }

    if let Some(a) = &l.applies {
        out.push(format!("    for {}", condition(a, 0)));
    }
    out.push(format!("    {}", window(&l.window.node)));
    if let Some(s) = &l.scope {
        out.push(format!("    scope {}", s.node.as_str()));
    }

    // Threshold triggers first, ascending; `when exhausted` last. S17 makes `above` and
    // `at least` one kind and S15 admits one of each, so no two thresholds can coexist and the
    // sort never has to break a tie.
    let mut escalations: Vec<(u8, String)> = l
        .escalations
        .iter()
        .map(|e| {
            let rank = matches!(e.trigger.node, Trigger::WhenExhausted) as u8;
            (rank, escalation(e))
        })
        .collect();
    escalations.sort();
    for (_, e) in escalations {
        out.push(format!("    {e}"));
    }

    out
}

fn escalation(e: &Escalation) -> String {
    let mut s = format!(
        "escalate {} require {} of {} up to {}",
        trigger(&e.trigger.node),
        e.quorum.node,
        e.approvers.node,
        exc_value(&e.ceiling.node)
    );
    // Durations keep the unit the author used: the unit is significant (§8.3) and is not
    // normalised, so `1 days` does not become `24 hours`.
    if let Some((n, unit)) = &e.within_text {
        s.push_str(&format!(" within {n} {unit}"));
    }
    s
}

fn trigger(t: &Trigger) -> String {
    match t {
        Trigger::Above(m) => format!("above {}", money(m)),
        Trigger::AtLeast(m) => format!("at least {}", money(m)),
        Trigger::AboveCount(n) => format!("above {n}"),
        Trigger::AtLeastCount(n) => format!("at least {n}"),
        Trigger::WhenExhausted => String::from("when exhausted"),
    }
}

fn exc_value(v: &ExcValue) -> String {
    match v {
        ExcValue::Money(m) => money(m),
        ExcValue::Count(n) => n.to_string(),
        ExcValue::Unlimited => String::from("unlimited"),
    }
}

/// Money as written, at the scale the source carried.
///
/// §1.2 asks for exactly the asset's declared minor-unit digits, which is a resolver fact.
/// This emitter re-emits the source scale, so it is canonical for a document whose literals
/// were already at the asset's scale and faithful otherwise — scaling belongs to the pass that
/// has `decimals`, and inventing digits here would be worse than preserving them.
fn money(m: &Money) -> String {
    if m.fraction.is_empty() {
        format!("{} {}", m.integer, m.asset.node)
    } else {
        format!("{}.{} {}", m.integer, m.fraction, m.asset.node)
    }
}

fn window(w: &Window) -> String {
    match w {
        Window::Rolling { count, unit, .. } => format!("per rolling {count} {unit}"),
        Window::Fixed { unit, tz: Some(tz) } => format!("per fixed {unit} in {tz}"),
        Window::Fixed { unit, tz: None } => format!("per fixed {unit}"),
    }
}

/// Precedence is `not` > `and` > `or`, left-associative (§3). Parenthesise only where the
/// structure needs it: emitting defensive parentheses would produce different bytes for the
/// same meaning depending on how the tree was built.
fn condition(c: &Condition, parent: u8) -> String {
    match c {
        Condition::Or(a, b) => {
            let s = format!("{} or {}", condition(a, 1), condition(b, 1));
            if parent > 1 {
                format!("({s})")
            } else {
                s
            }
        }
        Condition::And(a, b) => {
            let s = format!("{} and {}", condition(a, 2), condition(b, 2));
            if parent > 2 {
                format!("({s})")
            } else {
                s
            }
        }
        Condition::Not(a) => format!("not {}", condition(a, 3)),
        Condition::Compare(cmp) => {
            format!("{} {} {}", cmp.field.node, cmp.operator.node, value(&cmp.value.node))
        }
    }
}

fn value(v: &Value) -> String {
    match v {
        Value::Named(n) => n.clone(),
        Value::Literal(l) => l.to_string(),
        Value::Date(d) => d.clone(),
        Value::Plane(p) => p.clone(),
        Value::Set(items) => {
            // Items keep source order: set membership is unordered, but reordering buys
            // nothing and loses the author's grouping.
            let rendered: Vec<String> = items.iter().map(|i| value(&i.node)).collect();
            let refs: Vec<&str> = rendered.iter().map(|s| s.as_str()).collect();
            set(&refs)
        }
    }
}

/// `{ a, b, c }`: one space inside each brace, `, ` between items, no trailing comma.
fn set(items: &[&str]) -> String {
    format!("{{ {} }}", items.join(", "))
}
