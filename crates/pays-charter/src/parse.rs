//! Recursive descent, hand-written. No parser combinator library (a recorded decision).
//!
//! The grammar is LL(1) given §2.3's multi-word tokens: every declaration and every clause
//! within a limit is keyword-led, so a limit ends at the first token that cannot continue it.
//!
//! **This pass resolves no names** (§5.2). It places each identifier in a slot whose expected
//! kind is fixed by the grammar position, and a later pass compares that against the one
//! declaration table. That separation is what makes §7.1.1's attack a compile error rather
//! than an ambiguity: `require 2 of finance` cannot parse as anything but a request for an
//! approver set, whatever `finance` turns out to be declared as.

use crate::ast::*;
use crate::diag::Diagnostic;
use crate::lex::{lex, Span, Tok, Token};
use charter_assetref as aref;

pub fn parse(src: &str) -> Result<Charter, Vec<Diagnostic>> {
    let tokens = match lex(src) {
        Ok(t) => t,
        Err(e) => return Err(vec![Diagnostic::error(e.code, e.message, e.span)]),
    };
    let mut p = Parser { t: tokens, i: 0, errors: Vec::new(), end: src.len() };
    let charter = p.charter();
    match charter {
        Some(c) if p.errors.is_empty() => Ok(c),
        _ => {
            if p.errors.is_empty() {
                p.errors.push(Diagnostic::error("E101", "empty document", 0..src.len()));
            }
            Err(p.errors)
        }
    }
}

struct Parser {
    t: Vec<Token>,
    i: usize,
    errors: Vec<Diagnostic>,
    end: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i).map(|t| &t.tok)
    }

    fn span(&self) -> Span {
        self.t.get(self.i).map(|t| t.span.clone()).unwrap_or(self.end..self.end)
    }

    fn prev_span(&self) -> Span {
        self.t.get(self.i.saturating_sub(1)).map(|t| t.span.clone()).unwrap_or(self.end..self.end)
    }

    fn bump(&mut self) -> Option<Tok> {
        let t = self.t.get(self.i).map(|t| t.tok.clone());
        if t.is_some() {
            self.i += 1;
        }
        t
    }

    fn at_kw(&self, k: &str) -> bool {
        matches!(self.peek(), Some(Tok::Kw(x)) if *x == k)
    }

    fn eat_kw(&mut self, k: &str) -> bool {
        if self.at_kw(k) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn err(&mut self, code: &'static str, msg: impl Into<String>) {
        let span = self.span();
        self.errors.push(Diagnostic::error(code, msg, span));
    }

    fn expect_kw(&mut self, k: &'static str) -> bool {
        if self.eat_kw(k) {
            true
        } else {
            self.err("E101", format!("expected `{k}`, found {}", self.describe()));
            false
        }
    }

    fn describe(&self) -> String {
        match self.peek() {
            None => "end of input".into(),
            Some(Tok::Kw(k)) => format!("`{k}`"),
            Some(Tok::Ident(s)) => format!("identifier `{s}`"),
            Some(Tok::Int(n)) => format!("`{n}`"),
            Some(Tok::Dec(a, b)) => format!("`{a}.{b}`"),
            Some(Tok::Ref(r)) => format!("reference `{r}`"),
            Some(Tok::Tagged(t, v)) => format!("`{t}:{v}`"),
            Some(Tok::Addr(a)) => format!("address `{a}`"),
            Some(Tok::Date(d)) => format!("date `{d}`"),
            Some(t) => format!("{t:?}"),
        }
    }

    fn ident(&mut self) -> Option<Name> {
        let span = self.span();
        match self.bump() {
            Some(Tok::Ident(s)) => Some(Name::new(s, span)),
            // An address-shaped token is still a name in an ident position.
            Some(Tok::Addr(s)) => Some(Name::new(s, span)),
            _ => {
                self.i = self.i.saturating_sub(1);
                self.err("E101", format!("expected an identifier, found {}", self.describe()));
                self.i += 1;
                None
            }
        }
    }

    fn uint(&mut self) -> Option<Spanned<u64>> {
        let span = self.span();
        match self.bump() {
            Some(Tok::Int(n)) => Some(Spanned::new(n, span)),
            _ => {
                self.i = self.i.saturating_sub(1);
                self.err("E101", format!("expected an integer, found {}", self.describe()));
                self.i += 1;
                None
            }
        }
    }

    /// §2.1.2: resynchronise on the declaration keywords. A keyword-led grammar makes this
    /// both trivial and safe — every construct is reachable from that set, so recovery never
    /// has to guess.
    fn recover(&mut self) {
        const STARTS: &[&str] =
            &["asset", "instrument", "group", "approvers", "prohibit", "limit"];
        while let Some(t) = self.peek() {
            if let Tok::Kw(k) = t {
                if STARTS.contains(k) {
                    return;
                }
            }
            self.i += 1;
        }
    }

    fn charter(&mut self) -> Option<Charter> {
        if !self.expect_kw("charter") {
            return None;
        }
        let name = self.ident()?;
        self.expect_kw("version");
        let version = self.uint()?.node;

        let extends = if self.eat_kw("extends") {
            let n = self.ident()?;
            if !self.eat_kw("@") && !matches!(self.peek(), Some(Tok::At)) {
                // `@` is a punctuation token; accept it either way.
            }
            if matches!(self.peek(), Some(Tok::At)) {
                self.i += 1;
            }
            let v = self.uint()?.node;
            // E312. Two parents give a limit two ceilings with no defined composition, and
            // there is no rule in §8A that would pick between them — so it is refused here,
            // named, rather than left to fail at whatever the header expected next.
            while self.at_kw("extends") {
                self.err(
                    "E312",
                    "a charter extends exactly one parent. Two give a limit two ceilings and \
                     nothing in §8A composes them: H1 takes a minimum along one chain, and \
                     there is no minimum to take across two.",
                );
                self.i += 1;
                let _ = self.ident();
                if matches!(self.peek(), Some(Tok::At)) {
                    self.i += 1;
                }
                let _ = self.uint();
            }
            Some((n, v))
        } else {
            None
        };

        self.expect_kw("resolver");
        let tier_span = self.span();
        let tier = if self.eat_kw("common") {
            "common".to_string()
        } else if self.eat_kw("full") {
            "full".to_string()
        } else {
            self.err("E101", "a resolver tier is `common` or `full`");
            "common".to_string()
        };
        if matches!(self.peek(), Some(Tok::At)) {
            self.i += 1;
        }
        let rver = self.uint().map(|s| s.node).unwrap_or(0);

        self.expect_kw("timezone");
        let tz_span = self.span();
        let tz = self.timezone_text();

        let mut decls = Vec::new();
        while self.peek().is_some() {
            let before = self.i;
            match self.decl() {
                Some(d) => decls.push(d),
                None => {
                    if self.i == before {
                        self.i += 1;
                    }
                    self.recover();
                }
            }
        }

        Some(Charter {
            name,
            version,
            extends,
            resolver_tier: Spanned::new(tier, tier_span),
            resolver_version: rver,
            timezone: Spanned::new(tz, tz_span),
            decls,
        })
    }

    /// A timezone is `UTC` with an optional fixed offset (§2.9). No IANA names and no
    /// daylight saving: a boundary is arithmetic, so the enclave needs no database and a
    /// signed charter cannot change meaning when somebody legislates a clock change.
    ///
    /// The lexer hands `UTC+10:00` back in pieces — the sign is not an identifier character —
    /// so reassemble and validate here.
    fn timezone_text(&mut self) -> String {
        let span = self.span();
        if let Some(Tok::Tz(tz)) = self.peek().cloned() {
            self.i += 1;
            return self.check_offset(&tz, span);
        }

        let head = match self.peek().cloned() {
            Some(Tok::Ident(s)) => {
                self.i += 1;
                s
            }
            _ => {
                self.err("E206", "expected `UTC` or `UTC+HH:MM`");
                return "UTC+00:00".into();
            }
        };

        // An IANA name is the mistake worth naming, since it is what every other system takes.
        if matches!(self.peek(), Some(Tok::Slash)) || head.contains('/') {
            self.errors.push(Diagnostic::error(
                "E206",
                format!(
                    "`{head}/…` is an IANA zone name. This language takes a fixed UTC offset — \
                     `UTC+01:00` — because a window boundary must be arithmetic the enclave can \
                     do without a database, and because a tzdata update must not change what an \
                     already-signed charter means (§2.9)."
                ),
                span,
            ));
            while matches!(self.peek(), Some(Tok::Slash)) {
                self.i += 1;
                self.i += 1;
            }
            return "UTC+00:00".into();
        }

        if head != "UTC" {
            self.errors.push(Diagnostic::error(
                "E206",
                format!("expected `UTC` or `UTC+HH:MM`, found `{head}`"),
                span,
            ));
            return "UTC+00:00".into();
        }

        unreachable!("a UTC token is handled above")
    }

    /// The whole offset rule, in one place: shape, range and quarter-hour minutes (§2.9).
    ///
    /// The lexer decides only where the token ends. Everything wrong with an offset — a
    /// missing digit, a missing colon, a value out of range — is E206 from here, so a near
    /// miss like `UTC+1:00` is diagnosed as the offset it obviously meant to be rather than
    /// as an unexpected character.
    fn check_offset(&mut self, tz: &str, span: Span) -> String {
        let Some(off) = tz.strip_prefix("UTC") else { return "UTC+00:00".into() };
        if off.is_empty() {
            return "UTC+00:00".into();
        }

        let b = off.as_bytes();
        let shaped = b.len() == 6
            && (b[0] == b'+' || b[0] == b'-')
            && b[1].is_ascii_digit()
            && b[2].is_ascii_digit()
            && b[3] == b':'
            && b[4].is_ascii_digit()
            && b[5].is_ascii_digit();
        if !shaped {
            self.errors.push(Diagnostic::error(
                "E206",
                format!(
                    "an offset is `+HH:MM` or `-HH:MM`, two digits each side of the colon; \
                     found `{off}`"
                ),
                span,
            ));
            return "UTC+00:00".into();
        }

        let sign = &off[..1];
        let hh: i32 = off[1..3].parse().unwrap_or(0);
        let mm: i32 = off[4..6].parse().unwrap_or(0);

        if !matches!(mm, 0 | 15 | 30 | 45) {
            self.errors.push(Diagnostic::error(
                "E206",
                format!("offset minutes are 00, 15, 30 or 45; found {mm:02}"),
                span,
            ));
            return "UTC+00:00".into();
        }
        let total = if sign == "-" { -(hh * 60 + mm) } else { hh * 60 + mm };
        if !(-12 * 60..=14 * 60).contains(&total) {
            self.errors.push(Diagnostic::error(
                "E206",
                format!("an offset lies in -12:00 ..= +14:00; found {sign}{hh:02}:{mm:02}"),
                span,
            ));
            return "UTC+00:00".into();
        }
        format!("UTC{sign}{hh:02}:{mm:02}")
    }

    fn decl(&mut self) -> Option<Decl> {
        if self.at_kw("asset") {
            // Maximal munch already decided this: `asset group X` is two keywords, while
            // `asset group_solana` is a keyword and one identifier.
            if matches!(self.t.get(self.i + 1).map(|t| &t.tok), Some(Tok::Kw("group"))) {
                return self.asset_group().map(Decl::AssetGroup);
            }
            return self.asset().map(Decl::Asset);
        }
        if self.at_kw("instrument") {
            return self.instrument().map(Decl::Instrument);
        }
        if self.at_kw("group") {
            return self.group().map(Decl::Group);
        }
        if self.at_kw("approvers") {
            return self.approvers().map(Decl::Approvers);
        }
        if self.at_kw("prohibit") {
            return self.prohibit().map(Decl::Prohibit);
        }
        if self.at_kw("limit") {
            return self.limit().map(Decl::Limit);
        }
        self.err("E101", format!("expected a declaration, found {}", self.describe()));
        None
    }

    fn asset(&mut self) -> Option<AssetDecl> {
        self.expect_kw("asset");
        let name = self.ident()?;
        self.expect_eq();
        let span = self.span();
        let Some(Tok::Ref(text)) = self.bump() else {
            self.err("E410", "expected an asset reference");
            return None;
        };
        match aref::parse(&text, span.start) {
            Ok(r) => Some(AssetDecl { name, reference: Spanned::new(r, span) }),
            Err(e) => {
                self.errors.push(Diagnostic::error(e.code, e.message, e.span));
                None
            }
        }
    }

    fn asset_group(&mut self) -> Option<AssetGroupDecl> {
        self.expect_kw("asset");
        self.expect_kw("group");
        let name = self.ident()?;
        self.expect_eq();
        let members = self.brace_list(|p| p.ident())?;
        Some(AssetGroupDecl { name, members })
    }

    fn instrument(&mut self) -> Option<InstrumentDecl> {
        self.expect_kw("instrument");
        let name = self.ident()?;
        self.expect_eq();
        let span = self.span();
        let Some(Tok::Ref(text)) = self.bump() else {
            self.err("E218", "expected an instrument reference");
            return None;
        };
        let r = if let Some(rest) = text.strip_prefix("card://") {
            let mut it = rest.splitn(2, '/');
            match (it.next(), it.next()) {
                (Some(n), Some(h)) if !n.is_empty() && !h.is_empty() && !h.contains('/') => {
                    InstrumentRef::Card { network: n.into(), handle: h.into() }
                }
                _ => {
                    self.errors.push(Diagnostic::error(
                        "E218",
                        "a card reference is card://<network>/<handle>",
                        span,
                    ));
                    return None;
                }
            }
        } else if let Some(rest) = text.strip_prefix("wallet://") {
            let mut it = rest.splitn(2, '/');
            match (it.next(), it.next()) {
                (Some(c), Some(a)) if c.contains(':') && !a.is_empty() && !a.contains('/') => {
                    InstrumentRef::Wallet { chain: c.into(), address: a.into() }
                }
                _ => {
                    self.errors.push(Diagnostic::error(
                        "E218",
                        "a wallet reference is wallet://<caip2>/<address>",
                        span,
                    ));
                    return None;
                }
            }
        } else {
            self.errors.push(Diagnostic::error(
                "E218",
                "an instrument reference is card:// or wallet://",
                span,
            ));
            return None;
        };
        Some(InstrumentDecl { name, reference: Spanned::new(r, span) })
    }

    fn group(&mut self) -> Option<GroupDecl> {
        self.expect_kw("group");
        let name = self.ident()?;
        self.expect_eq();
        let members = self.brace_list(|p| {
            let span = p.span();
            match p.bump() {
                Some(Tok::Tagged(t, v)) => Some(Spanned::new(Literal::Tagged(t, v), span)),
                Some(Tok::Addr(a)) => Some(Spanned::new(Literal::Address(a), span)),
                Some(Tok::Ident(a)) => Some(Spanned::new(Literal::Address(a), span)),
                _ => {
                    p.err("E302", "a group member is an address or a tagged literal");
                    None
                }
            }
        })?;
        Some(GroupDecl { name, members })
    }

    fn approvers(&mut self) -> Option<ApproversDecl> {
        self.expect_kw("approvers");
        let name = self.ident()?;
        self.expect_eq();
        let members = self.brace_list(|p| p.ident())?;
        Some(ApproversDecl { name, members })
    }

    fn prohibit(&mut self) -> Option<ProhibitDecl> {
        self.expect_kw("prohibit");
        let name = self.ident()?;
        self.expect_kw("when");
        let condition = self.condition()?;
        Some(ProhibitDecl { name, condition })
    }

    fn limit(&mut self) -> Option<LimitDecl> {
        self.expect_kw("limit");
        let name = self.ident()?;
        let dimension = self.dimension()?;

        let applies = if self.eat_kw("for") { Some(self.condition()?) } else { None };

        let wspan = self.span();
        let window = self.window()?;

        let scope = if self.at_kw("scope") {
            let s = self.span();
            self.i += 1;
            let v = if self.eat_kw("account") {
                Scope::Account
            } else if self.eat_kw("agent") {
                Scope::Agent
            } else if self.eat_kw("instrument") {
                Scope::Instrument
            } else if self.eat_kw("counterparty") {
                Scope::Counterparty
            } else {
                self.err("E101", "a scope is account, agent, instrument or counterparty");
                Scope::Account
            };
            Some(Spanned::new(v, s))
        } else {
            None
        };

        let mut escalations = Vec::new();
        while self.at_kw("escalate") {
            if let Some(e) = self.escalation() {
                escalations.push(e);
            } else {
                break;
            }
        }

        Some(LimitDecl {
            name,
            dimension,
            applies,
            window: Spanned::new(window, wspan),
            scope,
            escalations,
        })
    }

    fn dimension(&mut self) -> Option<Dimension> {
        if self.eat_kw("amount") {
            let span = self.span();
            let m = self.money()?;
            let mut exceptions = Vec::new();
            while self.at_kw("except") {
                exceptions.push(self.exception(true)?);
            }
            Some(Dimension::Amount { base: Spanned::new(m, span), exceptions })
        } else if self.eat_kw("count") {
            let n = self.uint()?;
            let mut exceptions = Vec::new();
            while self.at_kw("except") {
                exceptions.push(self.exception(false)?);
            }
            Some(Dimension::Count { base: n, exceptions })
        } else {
            self.err("E101", format!("expected `amount` or `count`, found {}", self.describe()));
            None
        }
    }

    fn money(&mut self) -> Option<Money> {
        let (integer, fraction) = match self.bump() {
            Some(Tok::Dec(i, f)) => (i, f),
            Some(Tok::Int(i)) => (i, String::new()),
            _ => {
                self.i = self.i.saturating_sub(1);
                self.err("E101", format!("expected an amount, found {}", self.describe()));
                self.i += 1;
                return None;
            }
        };
        let asset = self.ident()?;
        Some(Money { integer, fraction, asset })
    }

    fn exception(&mut self, amount: bool) -> Option<Exception> {
        self.expect_kw("except");
        let span = self.span();
        let value = if self.at_kw("unlimited") {
            self.i += 1;
            Spanned::new(ExcValue::Unlimited, span)
        } else if amount {
            Spanned::new(ExcValue::Money(self.money()?), span)
        } else {
            Spanned::new(ExcValue::Count(self.uint()?.node), span)
        };
        self.expect_kw("when");
        let condition = self.condition()?;
        Some(Exception { value, condition })
    }

    fn window(&mut self) -> Option<Window> {
        self.expect_kw("per");
        if self.eat_kw("rolling") {
            let n = self.uint()?.node;
            let unit = self.time_unit()?;
            let secs = match unit.as_str() {
                "second" | "seconds" => 1,
                "minute" | "minutes" => 60,
                "hour" | "hours" => 3600,
                "day" | "days" => 86400,
                _ => 1,
            };
            Some(Window::Rolling { seconds: n.saturating_mul(secs), unit, count: n })
        } else if self.eat_kw("fixed") {
            let unit = self.cal_unit()?;
            let tz = if self.eat_kw("in") { Some(self.timezone_text()) } else { None };
            Some(Window::Fixed { unit, tz })
        } else {
            self.err("E101", "a window is `per rolling <duration>` or `per fixed <unit>`");
            None
        }
    }

    fn time_unit(&mut self) -> Option<String> {
        for u in ["seconds", "second", "minutes", "minute", "hours", "hour", "days", "day"] {
            if self.eat_kw(u) {
                return Some(u.to_string());
            }
        }
        self.err("E204", "expected a time unit");
        None
    }

    fn cal_unit(&mut self) -> Option<String> {
        for u in ["day", "week", "month", "year"] {
            if self.eat_kw(u) {
                return Some(u.to_string());
            }
        }
        self.err("E101", "a fixed window is per day, week, month or year");
        None
    }

    fn escalation(&mut self) -> Option<Escalation> {
        self.expect_kw("escalate");
        let tspan = self.span();
        let trigger = if self.eat_kw("when exhausted") {
            Trigger::WhenExhausted
        } else if self.eat_kw("above") {
            match self.peek() {
                Some(Tok::Dec(..)) => Trigger::Above(self.money()?),
                _ => {
                    let n = self.uint()?.node;
                    if matches!(self.peek(), Some(Tok::Ident(_))) {
                        let asset = self.ident()?;
                        Trigger::Above(Money { integer: n, fraction: String::new(), asset })
                    } else {
                        Trigger::AboveCount(n)
                    }
                }
            }
        } else if self.eat_kw("at least") {
            match self.peek() {
                Some(Tok::Dec(..)) => Trigger::AtLeast(self.money()?),
                _ => {
                    let n = self.uint()?.node;
                    if matches!(self.peek(), Some(Tok::Ident(_))) {
                        let asset = self.ident()?;
                        Trigger::AtLeast(Money { integer: n, fraction: String::new(), asset })
                    } else {
                        Trigger::AtLeastCount(n)
                    }
                }
            }
        } else {
            self.err("E101", "an escalation trigger is `above`, `at least` or `when exhausted`");
            return None;
        };

        self.expect_kw("require");
        let quorum = self.uint()?;
        self.expect_kw("of");
        let approvers = self.ident()?;
        self.expect_kw("up to");
        let cspan = self.span();
        let ceiling = match self.peek() {
            Some(Tok::Dec(..)) => Spanned::new(ExcValue::Money(self.money()?), cspan),
            _ => {
                let n = self.uint()?.node;
                if matches!(self.peek(), Some(Tok::Ident(_))) {
                    let asset = self.ident()?;
                    Spanned::new(
                        ExcValue::Money(Money { integer: n, fraction: String::new(), asset }),
                        cspan,
                    )
                } else {
                    Spanned::new(ExcValue::Count(n), cspan)
                }
            }
        };

        let (within, within_text) = if self.eat_kw("within") {
            let s = self.span();
            let n = self.uint()?.node;
            let unit = self.time_unit()?;
            let secs = match unit.as_str() {
                "second" | "seconds" => 1,
                "minute" | "minutes" => 60,
                "hour" | "hours" => 3600,
                _ => 86400,
            };
            (Some(Spanned::new(n.saturating_mul(secs), s)), Some((n, unit)))
        } else {
            (None, None)
        };

        Some(Escalation {
            trigger: Spanned::new(trigger, tspan),
            quorum,
            approvers,
            ceiling,
            within,
            within_text,
        })
    }

    // `not` > `and` > `or`, left-associative (§3).
    fn condition(&mut self) -> Option<Condition> {
        let mut lhs = self.conjunction()?;
        while self.eat_kw("or") {
            let rhs = self.conjunction()?;
            lhs = Condition::Or(Box::new(lhs), Box::new(rhs));
        }
        Some(lhs)
    }

    fn conjunction(&mut self) -> Option<Condition> {
        let mut lhs = self.negation()?;
        while self.eat_kw("and") {
            let rhs = self.negation()?;
            lhs = Condition::And(Box::new(lhs), Box::new(rhs));
        }
        Some(lhs)
    }

    fn negation(&mut self) -> Option<Condition> {
        if self.eat_kw("not") {
            return Some(Condition::Not(Box::new(self.negation()?)));
        }
        if matches!(self.peek(), Some(Tok::LParen)) {
            self.i += 1;
            let c = self.condition()?;
            if matches!(self.peek(), Some(Tok::RParen)) {
                self.i += 1;
            } else {
                self.err("E101", "expected `)`");
            }
            return Some(c);
        }
        Some(Condition::Compare(self.comparison()?))
    }

    fn comparison(&mut self) -> Option<Comparison> {
        let fspan = self.span();
        let field = self.field_name()?;

        let ospan = self.span();
        let operator = if self.eat_kw("is at least") {
            "is at least"
        } else if self.eat_kw("is not") {
            "is not"
        } else if self.eat_kw("not in") {
            "not in"
        } else if self.eat_kw("is") {
            "is"
        } else if self.eat_kw("in") {
            "in"
        } else if self.eat_kw("before") {
            "before"
        } else if self.eat_kw("after") {
            "after"
        } else {
            self.err("E301", format!("expected an operator, found {}", self.describe()));
            return None;
        };

        let vspan = self.span();
        let value = self.value()?;

        Some(Comparison {
            field: Spanned::new(field, fspan),
            operator: Spanned::new(operator.to_string(), ospan),
            value: Spanned::new(value, vspan),
        })
    }

    /// Dotted field names arrive as separate tokens; reassemble them here so the field set
    /// stays a closed enumeration checked in one place.
    fn field_name(&mut self) -> Option<String> {
        let base = match self.peek().cloned() {
            Some(Tok::Kw(k)) => {
                self.i += 1;
                k.to_string()
            }
            Some(Tok::Ident(s)) => {
                self.i += 1;
                s
            }
            _ => {
                self.err("E301", format!("expected a field, found {}", self.describe()));
                return None;
            }
        };
        // The lexer produces `asset.class` and `merchant.category` as one identifier when
        // written without spaces, because `.` is not an identifier character — so they arrive
        // as ident, Dot, ident only if spaced. Handle the joined form directly.
        Some(base)
    }

    fn value(&mut self) -> Option<Value> {
        if matches!(self.peek(), Some(Tok::LBrace)) {
            let items = self.brace_list(|p| {
                let s = p.span();
                p.value().map(|v| Spanned::new(v, s))
            })?;
            return Some(Value::Set(items));
        }
        let span = self.span();
        match self.bump() {
            Some(Tok::Ident(s)) => Some(Value::Named(s)),
            Some(Tok::Addr(a)) => Some(Value::Literal(Literal::Address(a))),
            Some(Tok::Tagged(t, v)) => Some(Value::Literal(Literal::Tagged(t, v))),
            Some(Tok::Date(d)) => Some(Value::Date(d)),
            Some(Tok::Kw(k)) if matches!(k, "principal" | "agent" | "merchant" | "network") => {
                Some(Value::Plane(k.to_string()))
            }
            _ => {
                self.errors.push(Diagnostic::error("E301", "expected a value", span));
                None
            }
        }
    }

    fn expect_eq(&mut self) {
        if matches!(self.peek(), Some(Tok::Eq)) {
            self.i += 1;
        } else {
            self.err("E101", format!("expected `=`, found {}", self.describe()));
        }
    }

    fn brace_list<T>(&mut self, mut item: impl FnMut(&mut Self) -> Option<T>) -> Option<Vec<T>> {
        if !matches!(self.peek(), Some(Tok::LBrace)) {
            self.err("E101", format!("expected `{{`, found {}", self.describe()));
            return None;
        }
        self.i += 1;
        let mut out = Vec::new();
        loop {
            if matches!(self.peek(), Some(Tok::RBrace)) {
                self.i += 1;
                break;
            }
            if self.peek().is_none() {
                let s = self.prev_span();
                self.errors.push(Diagnostic::error("E101", "unclosed `{`", s));
                return None;
            }
            out.push(item(self)?);
            if matches!(self.peek(), Some(Tok::Comma)) {
                self.i += 1;
            }
        }
        Some(out)
    }
}
