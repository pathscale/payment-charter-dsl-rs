//! Chains of charters (§8A) — company, department, manager, agent.
//!
//! A chain is linked from compiled documents, root first. Everything here is static: the
//! per-request half of §8A lives in [`crate::eval`], and the two are separated on purpose,
//! because the checks below are the ones an author wants at the moment they write the child
//! rather than the first time an agent is refused.
//!
//! A charter with no parent is a chain of one and every rule degenerates correctly at that
//! length. There is no special case for the unparented document, which is what keeps the
//! single-charter path and the chain path from drifting apart.

use crate::compiled::{Compiled, Dimension, Limit};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A finding about a chain rather than about a document.
///
/// It carries no span. The compiled form carries no text by construction, and a chain finding
/// is about two documents at once in any case — so it names the charter and the declaration,
/// which is what a caller needs to map it back to a span in whichever source it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainDiagnostic {
    /// The stable code from §10.
    pub code: &'static str,
    pub message: String,
    /// The charter the finding is against — always the child, never the parent: the parent is
    /// already installed and signed, and the document that can still be fixed is this one.
    pub charter: String,
    /// The declaration named in the message, when there is one.
    pub subject: Option<String>,
    pub severity: Severity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

impl ChainDiagnostic {
    fn error(code: &'static str, charter: &str, subject: Option<&str>, message: String) -> Self {
        Self {
            code,
            message,
            charter: charter.to_string(),
            subject: subject.map(str::to_string),
            severity: Severity::Error,
        }
    }

    fn warning(code: &'static str, charter: &str, subject: Option<&str>, message: String) -> Self {
        Self {
            code,
            message,
            charter: charter.to_string(),
            subject: subject.map(str::to_string),
            severity: Severity::Warning,
        }
    }

    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

/// A linked chain, root first and leaf last.
#[derive(Clone, Debug)]
pub struct Chain<'a> {
    levels: Vec<&'a Compiled>,
    warnings: Vec<ChainDiagnostic>,
}

impl<'a> Chain<'a> {
    /// Link the levels, root first, and run every static rule in §8A.
    ///
    /// Errors are returned; warnings are kept on the chain, because a warning must not stop an
    /// engine from evaluating and must still reach whoever is authoring.
    pub fn link(levels: Vec<&'a Compiled>) -> Result<Self, Vec<ChainDiagnostic>> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        if levels.is_empty() {
            return Err(alloc::vec![ChainDiagnostic::error(
                "E318",
                "",
                None,
                "a chain has at least one document".to_string(),
            )]);
        }

        check_linkage(&levels, &mut errors);
        // Only run the comparisons once the chain is known to be a chain. Against a
        // mislinked parent every one of them would report on a document that is not
        // actually above this one, and an author would be chasing findings about the
        // wrong pair.
        if errors.is_empty() {
            for i in 1..levels.len() {
                check_level(&levels[..i], levels[i], &mut errors, &mut warnings);
            }
        }

        if errors.is_empty() {
            Ok(Self { levels, warnings })
        } else {
            Err(errors)
        }
    }

    /// A chain of one. The common case, and it is the same type so no caller branches on it.
    pub fn single(c: &'a Compiled) -> Self {
        Self { levels: alloc::vec![c], warnings: Vec::new() }
    }

    /// Root first, leaf last.
    pub fn levels(&self) -> &[&'a Compiled] {
        &self.levels
    }

    pub fn leaf(&self) -> &'a Compiled {
        self.levels[self.levels.len() - 1]
    }

    pub fn root(&self) -> &'a Compiled {
        self.levels[0]
    }

    pub fn warnings(&self) -> &[ChainDiagnostic] {
        &self.warnings
    }
}

/// Each level's `extends` must name the level directly above it, by id and by version.
///
/// The pin is checked in both directions. A missing pin at the root is a chain the caller
/// failed to supply in full, and evaluating it would silently drop a company-wide ceiling —
/// the exact failure §8A exists to prevent, and one that produces allow decisions rather than
/// an error, so it has to stop here.
fn check_linkage(levels: &[&Compiled], errors: &mut Vec<ChainDiagnostic>) {
    if let Some((parent, v)) = &levels[0].extends {
        errors.push(ChainDiagnostic::error(
            "E318",
            &levels[0].charter_id,
            None,
            format!(
                "`{}` extends `{parent}@{v}`, which was not supplied. The root of a chain \
                 extends nothing: evaluating this one as a root would drop every ceiling above \
                 it and answer `allow` where the chain answers `deny`.",
                levels[0].charter_id
            ),
        ));
    }

    for i in 1..levels.len() {
        let child = levels[i];
        let parent = levels[i - 1];
        match &child.extends {
            None => errors.push(ChainDiagnostic::error(
                "E318",
                &child.charter_id,
                None,
                format!(
                    "`{}` extends nothing, so it cannot sit beneath `{}`",
                    child.charter_id, parent.charter_id
                ),
            )),
            Some((name, _)) if *name != parent.charter_id => errors.push(ChainDiagnostic::error(
                "E318",
                &child.charter_id,
                None,
                format!(
                    "`{}` extends `{name}`, but the level above it is `{}`",
                    child.charter_id, parent.charter_id
                ),
            )),
            // §8A: a child MAY evaluate under a *later* parent version — a parent that tightens
            // always propagates. An *earlier* one is a rollback beneath a document written
            // against a newer parent, which is how a ceiling gets quietly raised: install the
            // child, then swap the parent for the looser version it superseded.
            Some((_, pin)) if *pin > parent.version => errors.push(ChainDiagnostic::error(
                "E407",
                &child.charter_id,
                None,
                format!(
                    "`{}` is pinned to `{}@{pin}` and the supplied parent is version {}. A \
                     later parent is allowed and a rolled-back one is not: the pin is a floor.",
                    child.charter_id, parent.charter_id, parent.version
                ),
            )),
            Some(_) => {}
        }
    }
}

/// The concrete asset names a limit's declared name covers: a group's members, or the name
/// itself. S22 has already proved a group's members equivalent, so this is a lookup.
fn covers(c: &Compiled, name: &str) -> Vec<String> {
    match c.asset_groups.iter().find(|(g, _)| g == name) {
        Some((_, members)) => members.clone(),
        None => alloc::vec![name.to_string()],
    }
}

/// Limits at any ancestor level that can bind the same payment as `l`: same dimension, and at
/// least one concrete asset in common.
fn comparable<'b>(ancestors: &[&'b Compiled], child: &Compiled, l: &Limit) -> Vec<&'b Limit> {
    let mine = covers(child, &l.asset);
    let mut out = Vec::new();
    for a in ancestors {
        for p in &a.limits {
            if p.dimension != l.dimension {
                continue;
            }
            let theirs = covers(a, &p.asset);
            if mine.iter().any(|m| theirs.iter().any(|t| t == m)) {
                out.push(p);
            }
        }
    }
    out
}

fn check_level(
    ancestors: &[&Compiled],
    child: &Compiled,
    errors: &mut Vec<ChainDiagnostic>,
    warnings: &mut Vec<ChainDiagnostic>,
) {
    for l in &child.limits {
        // H5 is about money. A `count` bounds a rate rather than an asset, and requiring the
        // company to have declared a rate before a department may is a rule §8A does not make.
        if l.dimension == Dimension::Amount {
            for asset in covers(child, &l.asset) {
                let capped = ancestors.iter().any(|a| {
                    a.limits.iter().any(|p| {
                        p.dimension == Dimension::Amount
                            && covers(a, &p.asset).contains(&asset)
                    })
                });
                if !capped {
                    errors.push(ChainDiagnostic::error(
                        "E315",
                        &child.charter_id,
                        Some(&l.id),
                        format!(
                            "`{}` caps `{asset}`, which no level above it caps. There is no \
                             inheritance of permission by omission: a child cannot introduce an \
                             asset its parent never allowed, so every request against this \
                             limit would be denied.",
                            l.id
                        ),
                    ));
                }
            }
        }

        let peers = comparable(ancestors, child, l);
        if peers.is_empty() {
            continue;
        }

        // Comparing ceilings across different windows is sound in this one direction. A
        // parent's per-window ceiling caps any single request too, so a child number above it
        // can never be reached whatever the two windows are; a child number below it may well
        // be reachable, so the absence of a warning claims nothing.
        let parent_autonomous = peers.iter().map(|p| p.autonomous_ceiling()).min().unwrap_or(0);
        if l.autonomous_ceiling() > parent_autonomous {
            warnings.push(ChainDiagnostic::warning(
                "W2",
                &child.charter_id,
                Some(&l.id),
                format!(
                    "`{}` permits up to {} unaccompanied, above the {} its chain permits. A \
                     child may only tighten, so the larger number is dead text — the minimum \
                     still binds and nothing here raises it.",
                    l.id,
                    l.autonomous_ceiling(),
                    parent_autonomous
                ),
            ));
        }

        // H3. A quorum drawn at this level cannot answer a constraint imposed above it, so an
        // escalation reaching past what the chain permits is not merely dead text: an
        // interface would show "1 of dept_leads, up to 1000000" beneath a company cap of 200,
        // and the number a person reads before approving would be a fiction.
        // Only the `up to` values declared here, not `escalated_ceiling`, which folds in the
        // base. A base above the parent is dead text and W2 has just said so; E313 is the
        // narrower claim that a quorum named at this level reaches past the chain.
        let parent_escalated = peers.iter().map(|p| p.escalated_ceiling()).min().unwrap_or(0);
        let reach = l.escalations.iter().map(|e| e.ceiling).max().unwrap_or(0);
        if reach > parent_escalated {
            errors.push(ChainDiagnostic::error(
                "E313",
                &child.charter_id,
                Some(&l.id),
                format!(
                    "`{}` escalates to {reach}, above the {} its chain permits even with approval. \
                     Escalation is answered by the level that imposed the constraint: approvers \
                     named here cannot authorise past a ceiling set above them.",
                    l.id,
                    parent_escalated
                ),
            ));
        }
    }
}

impl<'a> Chain<'a> {
    /// The static ceiling of a limit **within this chain** (S5, lifted by H4).
    ///
    /// A limit's own [`Limit::escalated_ceiling`] is what the document states, and for a limit
    /// carrying `unlimited` that is not what it can resolve to: the word means "this level adds
    /// no constraint", so at evaluation the ceiling becomes the parent's, which is larger than
    /// anything written here. Reading the document's own number would make the invariant report
    /// a violation on a payment the chain permits — an alarm that fires precisely when the
    /// language is working.
    ///
    /// It is an upper bound rather than the number itself: the parent's *resolved* ceiling for a
    /// given request can only be lower than its static one, so nothing this admits was refused.
    pub fn static_ceiling(&self, depth: usize, limit: &Limit) -> u64 {
        let own = limit.escalated_ceiling().max(limit.autonomous_ceiling());
        let inherits = limit
            .exceptions
            .iter()
            .any(|(_, v)| matches!(v, crate::compiled::ExcValue::Unlimited(_)));
        if !inherits || depth == 0 {
            return own;
        }
        let peers = comparable(&self.levels[..depth], self.levels[depth], limit);
        match peers
            .iter()
            .map(|p| p.escalated_ceiling().max(p.autonomous_ceiling()))
            .min()
        {
            Some(parent) => own.max(parent),
            // Nothing above bounds it. The engine denies such a request outright (H4), so no
            // exposure can arise and the document's own number is still the bound.
            None => own,
        }
    }

    /// The depth of a level by charter id, for a caller holding an accumulator key rather than
    /// an index.
    pub fn depth_of(&self, charter_id: &str) -> Option<usize> {
        self.levels.iter().position(|c| c.charter_id == charter_id)
    }
}
