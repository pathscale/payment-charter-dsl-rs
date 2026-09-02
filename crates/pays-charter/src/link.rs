//! Linking a chain of charters (§8A), with findings pointed back at the text.
//!
//! [`pays_policy::hierarchy`] does the work and knows nothing about source: the compiled form
//! carries no spans by construction, which is the whole reason the enclave can link it. This
//! module is the other half — it holds the ASTs, so it can turn "`weekly_travel` escalates
//! above what its chain permits" into a line and column in the document the author is editing.

use crate::ast::{Charter, Decl};
use crate::diag::Diagnostic;
use crate::lex::Span;
use pays_policy::compiled::Compiled;
use pays_policy::hierarchy::{Chain, ChainDiagnostic, Severity as ChainSeverity};

/// One level of a chain: the document and what it compiled to.
pub struct Level<'a> {
    pub ast: &'a Charter,
    pub compiled: &'a Compiled,
}

impl<'a> Level<'a> {
    pub fn new(ast: &'a Charter, compiled: &'a Compiled) -> Self {
        Self { ast, compiled }
    }
}

/// Link the levels, root first, and map every finding to a span in the document it is against.
///
/// Warnings come back beside the chain rather than instead of it: a chain that only warns is
/// still a chain, and W2 in particular is information an author wants while the document still
/// exists in an editor.
pub fn link<'a>(levels: &[Level<'a>]) -> Result<(Chain<'a>, Vec<Diagnostic>), Vec<Diagnostic>> {
    let compiled: Vec<&'a Compiled> = levels.iter().map(|l| l.compiled).collect();
    match Chain::link(compiled) {
        Ok(chain) => {
            let warnings = chain.warnings().iter().map(|w| map(w, levels)).collect();
            Ok((chain, warnings))
        }
        Err(errors) => Err(errors.iter().map(|e| map(e, levels)).collect()),
    }
}

/// The span for a chain finding: the named declaration where there is one, the `charter` line
/// otherwise.
///
/// Falling back to the header is deliberate. A linkage error is about the document as a whole
/// — its `extends` line is what is wrong — and an error with no span is one a reviewer cannot
/// act on, which §10 forbids.
fn map(d: &ChainDiagnostic, levels: &[Level]) -> Diagnostic {
    let span = levels
        .iter()
        .find(|l| l.ast.name.node == d.charter)
        .map(|l| match &d.subject {
            Some(name) => l
                .ast
                .decls
                .iter()
                .find(|decl| decl.name().node == *name)
                .map(|decl| decl.name().span.clone())
                .unwrap_or_else(|| l.ast.name.span.clone()),
            None => l.ast.name.span.clone(),
        })
        .unwrap_or(Span { start: 0, end: 0 });

    match d.severity {
        ChainSeverity::Error => Diagnostic::error(d.code, d.message.clone(), span),
        ChainSeverity::Warning => Diagnostic::warning(d.code, d.message.clone(), span),
    }
}

/// The declarations a level names, for a caller walking a chain without touching the AST.
pub fn declaration_names(c: &Charter) -> Vec<&str> {
    c.decls.iter().map(|d: &Decl| d.name().node.as_str()).collect()
}
