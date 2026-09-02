//! Diagnostics.
//!
//! Every error names a stable code from §10 and a source span. A charter is reviewed by
//! people who did not write it, so an error that cannot point at the text is an error nobody
//! can act on.

use crate::lex::Span;
use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub severity: Severity,
    /// `E304`, `W5`, … — stable so two implementations report the same thing.
    pub code: &'static str,
    pub message: String,
    pub span: Span,
    /// A second span when a rule is about two things at once. §10 requires every error over
    /// two rules to name both.
    pub related: Option<(Span, String)>,
}

impl Diagnostic {
    pub fn error(code: &'static str, message: impl Into<String>, span: Span) -> Self {
        Self { severity: Severity::Error, code, message: message.into(), span, related: None }
    }

    pub fn warning(code: &'static str, message: impl Into<String>, span: Span) -> Self {
        Self { severity: Severity::Warning, code, message: message.into(), span, related: None }
    }

    pub fn with_related(mut self, span: Span, note: impl Into<String>) -> Self {
        self.related = Some((span, note.into()));
        self
    }

    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }

    /// Render with a line and column, which is what a reviewer needs to find the text.
    pub fn render(&self, src: &str) -> String {
        let (line, col) = line_col(src, self.span.start);
        let kind = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        let mut s = format!("{kind}[{}]: {} at {line}:{col}", self.code, self.message);
        if let Some((rspan, note)) = &self.related {
            let (rl, rc) = line_col(src, rspan.start);
            s.push_str(&format!("\n  note: {note} at {rl}:{rc}"));
        }
        s
    }
}

fn line_col(src: &str, at: usize) -> (usize, usize) {
    let upto = &src[..at.min(src.len())];
    let line = upto.matches('\n').count() + 1;
    let col = upto.rsplit('\n').next().map_or(1, |l| l.chars().count() + 1);
    (line, col)
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
