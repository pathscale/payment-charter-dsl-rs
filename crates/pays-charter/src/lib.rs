//! Compiles a Payment Charter: lexer, parser, static rules, diagnostics, emitter.
//!
//! This half MAY take dependencies — it runs in the backend and the CLI. The evaluator lives
//! in `pays-policy`, is dependency-free, and never parses text: that split is the reason the
//! enclave can link one and not the other.

#![forbid(unsafe_code)]

pub mod ast;
pub mod diag;
pub mod lex;
pub mod parse;

pub use diag::{Diagnostic, Severity};
pub use parse::parse;
