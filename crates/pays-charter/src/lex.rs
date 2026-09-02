//! The lexer.
//!
//! Two rules from spec §2 do all the security work here, and both are easy to get subtly
//! wrong:
//!
//! **Maximal munch (§2.4).** Find the longest identifier, *then* ask whether it is a reserved
//! word. An attacker who mints a token with the symbol `group` forces the alias `group_solana`
//! (S19), and a lexer matching keywords eagerly would read `asset group_solana = …` as the
//! `asset group` production — a token boundary the author never wrote.
//!
//! **Longest match on multi-word operators (§2.3).** `is at least` is one token and must never
//! be lexed as `is` followed by `at least`, which are a comparison operator and an escalation
//! trigger respectively.
//!
//! There are no escapes and no quoting anywhere in the language (§2.4), so there is no string
//! state, no escape decoding, and nothing here that can disagree with another implementation
//! about what a document says.

use core::ops::Range;

pub type Span = Range<usize>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok {
    /// A reserved word, or a multi-word operator joined by single spaces.
    Kw(&'static str),
    Ident(String),
    /// An unsigned integer with `_` separators already stripped.
    Int(u64),
    /// A decimal as written: (integer part, fractional digits as written).
    Dec(u64, String),
    /// A `mint://`, `unit://`, `asset://` or bare CAIP-19 reference, undecomposed.
    Ref(String),
    /// `mcc:5411`, `country:PRK`, `class:fiat_reserve`.
    Tagged(String, String),
    /// A bare address literal in a group.
    Addr(String),
    Date(String),
    Eq,
    LBrace,
    RBrace,
    Comma,
    LParen,
    RParen,
    At,
    Dot,
    /// Only reached by an IANA zone name, which §2.9 no longer takes; kept so that
    /// mistake gets a diagnostic naming the replacement rather than a lexical error.
    Slash,
    /// A whole timezone: `UTC` or `UTC+HH:MM` (§2.9). One token, because a sign and a
    /// colon are otherwise three tokens that mean nothing on their own.
    Tz(String),
}

#[derive(Clone, Debug)]
pub struct Token {
    pub tok: Tok,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct LexError {
    pub code: &'static str,
    pub message: String,
    pub span: Span,
}

/// §2.3. Single words only; the multi-word forms are in `MULTI`.
pub const RESERVED: &[&str] = &[
    "above", "account", "agent", "amount", "and", "approvers", "asset", "at", "after", "before",
    "category", "charter", "common", "count", "counterparty", "date", "day", "days", "deny",
    "escalate", "except", "exhausted", "extends", "fixed", "for", "full", "group", "hour",
    "hours", "in", "instrument", "is", "least", "limit", "merchant", "minute", "minutes",
    "month", "network", "not", "of", "or", "per", "policy", "principal", "prohibit", "provenance",
    "require", "resolver", "rolling", "scope", "second", "seconds", "timezone", "to", "unlimited",
    "up", "version", "week", "when", "within", "year",
];

/// Longest first: `is at least` must win over `at least`, and both over their prefixes.
const MULTI: &[&str] = &["is at least", "when exhausted", "is not", "not in", "at least", "up to"];

/// Reserved words that are no longer usable, and the error that says so. Reserving a stale
/// keyword turns an old document into a clear diagnostic rather than a confusing parse.
fn retired(word: &str) -> Option<(&'static str, &'static str)> {
    match word {
        "deny" => Some(("E103", "`deny` is no longer a value; prohibition is its own declaration (§8.2.1)")),
        "policy" => Some(("E101", "`policy` was the opening keyword in an earlier draft; use `charter`")),
        _ => None,
    }
}

pub fn lex(src: &str) -> Result<Vec<Token>, LexError> {
    let b = src.as_bytes();
    let mut i = 0usize;
    let mut out = Vec::new();

    // A leading U+FEFF MUST be ignored (§2.1).
    if src.starts_with('\u{feff}') {
        i += '\u{feff}'.len_utf8();
    }

    while i < b.len() {
        let c = b[i] as char;

        if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
            i += 1;
            continue;
        }
        if c == '#' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        let start = i;

        let single = |t: Tok, i: &mut usize| {
            *i += 1;
            Some(Token { tok: t, span: start..*i })
        };
        if let Some(t) = match c {
            '=' => single(Tok::Eq, &mut i),
            '{' => single(Tok::LBrace, &mut i),
            '}' => single(Tok::RBrace, &mut i),
            ',' => single(Tok::Comma, &mut i),
            '(' => single(Tok::LParen, &mut i),
            ')' => single(Tok::RParen, &mut i),
            '@' => single(Tok::At, &mut i),
            '/' => single(Tok::Slash, &mut i),
            _ => None,
        } {
            out.push(t);
            continue;
        }

        // A timezone is one token. Tried before identifiers so the sign and colon of an
        // offset never become punctuation nobody can use.
        if let Some(len) = tz_len(&src[i..]) {
            out.push(Token { tok: Tok::Tz(src[i..i + len].to_string()), span: start..i + len });
            i += len;
            continue;
        }

        // A reference is one token, decomposed later by charter-assetref.
        if let Some(len) = reference_len(&src[i..]) {
            out.push(Token { tok: Tok::Ref(src[i..i + len].to_string()), span: start..i + len });
            i += len;
            continue;
        }

        if c.is_ascii_digit() {
            // An address may begin with a digit — base58 admits `3n1LSbDq…` — so measure the
            // whole alphanumeric run before deciding this is a number. Getting this wrong
            // silently truncates an address into an integer followed by a name.
            let mut j = i;
            while j < b.len() && (b[j] as char).is_ascii_alphanumeric() {
                j += 1;
            }
            if is_addr(&src[i..j]) {
                out.push(Token { tok: Tok::Addr(src[i..j].to_string()), span: start..j });
                i = j;
                continue;
            }
            let (tok, len) = lex_number(&src[i..], start)?;
            out.push(Token { tok, span: start..i + len });
            i += len;
            continue;
        }

        if c.is_ascii_alphabetic() || c == '_' {
            // Maximal munch, then keyword lookup. Never the other way round.
            let mut j = i;
            while j < b.len() {
                let ch = b[j] as char;
                if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                    j += 1;
                } else if ch == '.'
                    && b.get(j + 1).is_some_and(|n| (*n as char).is_ascii_alphabetic())
                {
                    // A dotted field name is one token: merchant.category, asset.class,
                    // provenance.recipient. A declaration name may not contain a dot, which
                    // the parser checks where names are bound.
                    j += 2;
                } else {
                    break;
                }
            }
            let word = &src[i..j];

            // A tagged literal: the tag is an identifier followed by ':'.
            if j < b.len() && b[j] == b':' {
                let mut k = j + 1;
                while k < b.len() {
                    let ch = b[k] as char;
                    if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                        k += 1;
                    } else {
                        break;
                    }
                }
                out.push(Token {
                    tok: Tok::Tagged(word.to_string(), src[j + 1..k].to_string()),
                    span: start..k,
                });
                i = k;
                continue;
            }

            if word.len() > 64 {
                return Err(LexError {
                    code: "E101",
                    message: format!("an identifier is at most 64 characters, found {}", word.len()),
                    span: start..j,
                });
            }

            // Multi-word operators, longest first, only when the first word matches exactly.
            if let Some(m) = MULTI.iter().find(|m| {
                m.split(' ').next() == Some(word) && matches_words(src, i, m)
            }) {
                let len = multi_len(src, i, m);
                out.push(Token { tok: Tok::Kw(m), span: start..i + len });
                i += len;
                continue;
            }

            if let Some((code, message)) = retired(word) {
                return Err(LexError { code, message: message.to_string(), span: start..j });
            }

            if let Some(kw) = RESERVED.iter().find(|k| **k == word) {
                out.push(Token { tok: Tok::Kw(kw), span: start..j });
            } else if is_addr(word) {
                out.push(Token { tok: Tok::Addr(word.to_string()), span: start..j });
            } else {
                out.push(Token { tok: Tok::Ident(word.to_string()), span: start..j });
            }
            i = j;
            continue;
        }

        return Err(LexError {
            code: "E101",
            message: format!("unexpected character {c:?}"),
            span: start..start + c.len_utf8(),
        });
    }
    Ok(out)
}

/// A bare address in a group: long, mixed-case alphanumeric with no separators. Kept distinct
/// from an identifier so `group x = { 7xKX… }` does not look like a name reference.
fn is_addr(w: &str) -> bool {
    w.len() >= 32 && w.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn matches_words(src: &str, at: usize, phrase: &str) -> bool {
    multi_len_opt(src, at, phrase).is_some()
}

fn multi_len(src: &str, at: usize, phrase: &str) -> usize {
    multi_len_opt(src, at, phrase).expect("checked by matches_words")
}

/// Match a multi-word operator across arbitrary whitespace, since newlines are not
/// terminators (§2.1) and `is\n  at least` is one token.
fn multi_len_opt(src: &str, at: usize, phrase: &str) -> Option<usize> {
    let b = src.as_bytes();
    let mut i = at;
    for (n, word) in phrase.split(' ').enumerate() {
        if n > 0 {
            let ws = i;
            while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\r' | b'\n') {
                i += 1;
            }
            if i == ws {
                return None;
            }
        }
        if !src[i..].starts_with(word) {
            return None;
        }
        let end = i + word.len();
        // The word must end here: `is` must not match the start of `island`.
        if end < b.len() {
            let ch = b[end] as char;
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                return None;
            }
        }
        i = end;
    }
    Some(i - at)
}

/// A reference token, recognised by its scheme or by the CAIP-19 shape.
fn reference_len(s: &str) -> Option<usize> {
    let schemes = ["mint://", "unit://", "asset://", "card://", "wallet://"];
    let is_scheme = schemes.iter().any(|p| s.starts_with(p));
    let is_caip19 = {
        // `<ns>:<ref>/<asset-ns>:<asset-ref>` — a colon before a slash, and no `//`.
        let end = s.find(|c: char| c.is_whitespace() || c == ',' || c == '}').unwrap_or(s.len());
        let head = &s[..end];
        !head.contains("://")
            && head.matches('/').count() == 1
            && head.matches(':').count() == 2
            && head.find(':').is_some_and(|c| head.find('/').is_some_and(|sl| c < sl))
    };
    if !is_scheme && !is_caip19 {
        return None;
    }
    let end = s
        .find(|c: char| c.is_whitespace() || c == ',' || c == '}' || c == ')')
        .unwrap_or(s.len());
    Some(end)
}

fn lex_number(s: &str, start: usize) -> Result<(Tok, usize), LexError> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut digits = String::new();

    while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'_') {
        if b[i] == b'_' {
            // A separator must not lead, trail, or follow '.' (§2.5).
            if i == 0 || !b[i - 1].is_ascii_digit() || i + 1 >= b.len() || !b[i + 1].is_ascii_digit()
            {
                return Err(LexError {
                    code: "E101",
                    message: "`_` in a number separates digits".into(),
                    span: (start + i)..(start + i + 1),
                });
            }
        } else {
            digits.push(b[i] as char);
        }
        i += 1;
    }

    // A date is three integers joined by '-': 2026-12-20.
    if i < b.len() && b[i] == b'-' && digits.len() == 4 {
        let mut j = i;
        let mut text = digits.clone();
        for _ in 0..2 {
            if j >= b.len() || b[j] != b'-' {
                break;
            }
            text.push('-');
            j += 1;
            let d0 = j;
            while j < b.len() && b[j].is_ascii_digit() {
                text.push(b[j] as char);
                j += 1;
            }
            if j == d0 {
                break;
            }
        }
        if text.len() == 10 {
            return Ok((Tok::Date(text), j));
        }
    }

    let int: u64 = digits.parse().map_err(|_| LexError {
        code: "E102",
        message: "integer does not fit in 64 bits".into(),
        span: start..(start + i),
    })?;

    if i < b.len() && b[i] == b'.' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
        i += 1;
        let mut frac = String::new();
        while i < b.len() && b[i].is_ascii_digit() {
            frac.push(b[i] as char);
            i += 1;
        }
        return Ok((Tok::Dec(int, frac), i));
    }
    Ok((Tok::Int(int), i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        lex(s).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn maximal_munch_defeats_the_hostile_symbol() {
        // The attack from §7.1.1: a token whose symbol is `group` forces the alias
        // `group_solana`, and an eager keyword matcher would see the `asset group` production.
        let t = toks("asset group_solana =");
        assert_eq!(
            t,
            vec![Tok::Kw("asset"), Tok::Ident("group_solana".into()), Tok::Eq],
            "group_solana is one identifier, never `group` followed by `_solana`"
        );
        // And the real production still lexes as two keywords.
        let t = toks("asset group USDC_circle_group =");
        assert_eq!(t[0], Tok::Kw("asset"));
        assert_eq!(t[1], Tok::Kw("group"));
        assert_eq!(t[2], Tok::Ident("USDC_circle_group".into()));
    }

    #[test]
    fn is_at_least_beats_at_least() {
        assert_eq!(toks("provenance is at least merchant")[1], Tok::Kw("is at least"));
        assert_eq!(toks("escalate at least 50")[1], Tok::Kw("at least"));
    }

    #[test]
    fn multi_word_operators_cross_newlines() {
        // Newlines are not terminators (§2.1), so a wrapped operator is still one token.
        assert_eq!(toks("is\n    at least merchant")[0], Tok::Kw("is at least"));
        assert_eq!(toks("when\texhausted")[0], Tok::Kw("when exhausted"));
    }

    #[test]
    fn a_keyword_prefix_is_not_a_keyword() {
        assert_eq!(toks("island")[0], Tok::Ident("island".into()));
        assert_eq!(toks("uptown")[0], Tok::Ident("uptown".into()));
        assert_eq!(toks("forx")[0], Tok::Ident("forx".into()));
    }

    #[test]
    fn retired_words_say_so() {
        let e = lex("except deny when").unwrap_err();
        assert_eq!(e.code, "E103");
        let e = lex("policy foo").unwrap_err();
        assert_eq!(e.code, "E101");
    }

    #[test]
    fn references_are_one_token() {
        let t = toks("asset USDC_circle = mint://USDC/Circle/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
        assert!(matches!(t[3], Tok::Ref(_)));
        let t = toks("asset X = asset://solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/token:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        assert!(matches!(t[3], Tok::Ref(_)));
        let t = toks("asset X = solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/token:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        assert!(matches!(t[3], Tok::Ref(_)), "bare CAIP-19 is a reference too: {:?}", t[3]);
    }

    #[test]
    fn money_and_counts() {
        assert_eq!(toks("100.00 USDC_circle")[0], Tok::Dec(100, "00".into()));
        assert_eq!(toks("20")[0], Tok::Int(20));
        assert_eq!(toks("1_000_000")[0], Tok::Int(1000000));
        assert!(lex("1__0").is_err());
        assert!(lex("_1").is_ok(), "a leading underscore starts an identifier, not a number");
    }

    #[test]
    fn dates_and_tags() {
        assert_eq!(toks("2026-12-20")[0], Tok::Date("2026-12-20".into()));
        assert_eq!(toks("mcc:5411")[0], Tok::Tagged("mcc".into(), "5411".into()));
        assert_eq!(toks("class:fiat_reserve")[0], Tok::Tagged("class".into(), "fiat_reserve".into()));
    }

    #[test]
    fn comments_and_layout_are_insignificant() {
        let a = toks("limit x\n  amount 5 USDC_c # trailing\n  per fixed day");
        let b = toks("limit x amount 5 USDC_c per fixed day");
        assert_eq!(a, b, "a conforming document MAY be written on one line");
    }

    #[test]
    fn no_escapes_exist() {
        // There is no string type and no escape mechanism anywhere (§2.4). A quote and a
        // backslash are both simply not characters this language contains.
        assert!(lex("asset \"USDC\" = x").is_err(), "no quoting");
        assert!(lex("asset US\\u0043 = x").is_err(), "no escape sequences");
        // Non-ASCII is confined to comments, so a homoglyph cannot reach an identifier and
        // slip past S19's byte comparison.
        assert!(lex("asset USDС_circle = x").is_err(), "Cyrillic С is not an identifier char");
        assert!(lex("# Cyrillic С is fine in a comment\nlimit x").is_ok());
    }
}

/// A timezone: `UTC` or `UTC±HH:MM` (§2.9). No zone names, no database, no daylight saving.
///
/// Matched as one token because a sign and a colon are meaningless separately here, and
/// because `-` is an identifier character — `UTC-05` would otherwise be swallowed whole and
/// `+10:00` would be an integer followed by punctuation nothing accepts.
///
/// Returns `None` for an identifier that merely starts with `UTC`, so an asset alias like
/// `UTC_pool` is unaffected.
///
/// The lexer decides only **where the token ends**, never whether it is well formed. Once a
/// sign follows `UTC` this is a timezone, and every complaint about it — wrong digit count,
/// missing colon, out of range, odd minutes — is one E206 from [`check_offset`].
///
/// The alternative, tried first, was to match only the exact shape and let anything else fall
/// through. `UTC+1:00` then reached the punctuation matcher and produced "unexpected character
/// `+`": a lexical error for an obvious typo, and a shape rule enforced by a token failing to
/// match rather than by anything a reader could find in the spec.
fn tz_len(s: &str) -> Option<usize> {
    let rest = s.strip_prefix("UTC")?;
    let b = rest.as_bytes();

    let len = match b.first() {
        // A sign commits this to being a timezone. Take the whole offset-shaped run and let
        // the parser say what is wrong with it.
        Some(b'+') | Some(b'-') => {
            let mut n = 1;
            while n < b.len() && (b[n].is_ascii_digit() || b[n] == b':') {
                n += 1;
            }
            3 + n
        }
        _ => 3,
    };

    // Bare `UTC` must still end here: `UTC_pool` and `UTCX` are identifiers.
    if let Some(next) = s.as_bytes().get(len) {
        let c = *next as char;
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            return None;
        }
    }
    Some(len)
}

#[cfg(test)]
mod tz_tests {
    use super::*;

    fn first(s: &str) -> Tok {
        lex(s).unwrap().into_iter().next().unwrap().tok
    }

    #[test]
    fn a_timezone_is_one_token() {
        assert_eq!(first("UTC"), Tok::Tz("UTC".into()));
        assert_eq!(first("UTC+10:00"), Tok::Tz("UTC+10:00".into()));
        assert_eq!(first("UTC-05:00"), Tok::Tz("UTC-05:00".into()));
        assert_eq!(first("UTC+05:45"), Tok::Tz("UTC+05:45".into()));
    }

    #[test]
    fn an_identifier_starting_with_utc_is_not_a_timezone() {
        // `-` is an identifier character, so `UTC-05` would otherwise be swallowed whole.
        assert_eq!(first("UTC_pool"), Tok::Ident("UTC_pool".into()));
        assert_eq!(first("UTCX"), Tok::Ident("UTCX".into()));
    }
}
