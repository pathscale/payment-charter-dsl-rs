//! Compiles a Payment Charter: lexer, parser, static rules, diagnostics, emitter.
//!
//! This half MAY take dependencies — it runs in the backend and the CLI. The evaluator lives
//! in `pays-policy`, is dependency-free, and never parses text.

#![forbid(unsafe_code)]

pub mod lex;
