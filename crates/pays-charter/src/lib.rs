//! Compiles a Payment Charter: lexer, parser, static rules, diagnostics, emitter.
//!
//! This half MAY take dependencies — it runs in the backend and the CLI. The evaluator lives
//! in `pays-policy`, is dependency-free, and never parses text: that split is the reason the
//! enclave can link one and not the other.

#![forbid(unsafe_code)]

pub mod ast;
pub mod compile;
pub mod diag;
pub mod emit;
pub mod lex;
pub mod json;
pub mod parse;
pub mod resolver;
pub mod rules;

pub use diag::{Diagnostic, Severity};
pub use compile::compile;
pub use resolver::Resolver;
pub use emit::emit;
pub use parse::parse;

/// Parse and apply the static rules. Errors and warnings come back together; a caller that
/// wants only errors filters on [`Diagnostic::is_error`].
///
/// Rules needing the resolver (S7–S13, and the minor-unit checks of §2.6) are not applied
/// here. A document this accepts has satisfied every rule that can be decided from the text
/// alone, which is not the same as compiling.
pub fn check(src: &str) -> Result<(ast::Charter, Vec<Diagnostic>), Vec<Diagnostic>> {
    let charter = parse(src)?;
    let diags = rules::check(&charter);
    if diags.iter().any(|d| d.is_error()) {
        Err(diags)
    } else {
        Ok((charter, diags))
    }
}
