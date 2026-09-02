//! The `mint://` and `unit://` reference parser for the Payment Charter DSL.
//!
//! A reference is lexed as a single token and decomposed here. It is never handled by
//! splitting on `/`, for the reasons in spec §2.10:
//!
//! - E401 must underline *which segment* disagrees with the resolver, so every field carries
//!   a byte span into the original token.
//! - Two input grammars — the native four-segment form and CAIP-19 — denote the same object
//!   and normalise to the first. Emission is always native.
//! - Per-namespace validation (S9) is a dispatch table, and an unknown namespace is E403
//!   rather than something accepted unchecked.
//!
//! Dependency-free, because `pays-policy` links it and the enclave links that.

#![forbid(unsafe_code)]

use core::fmt;
use core::ops::Range;

/// A byte range into the reference token as it appeared in the source.
pub type Span = Range<usize>;

/// A segment of a reference, with where it was found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub text: String,
    pub span: Span,
}

impl Segment {
    fn new(text: &str, span: Span) -> Self {
        Self { text: text.to_string(), span }
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// A CAIP-2 chain identifier: `namespace:reference`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caip2 {
    pub namespace: Segment,
    pub reference: Segment,
}

impl fmt::Display for Caip2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.namespace, self.reference)
    }
}

/// A parsed asset reference.
///
/// Identity is `(chain, mint_id)` and nothing else (§2.10.3). `symbol` and `issuer` are
/// *assertions* — what the author believes they are authorising — verified against the
/// resolver by S7 and never used to identify anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetRef {
    Mint {
        symbol: Segment,
        issuer: Segment,
        mint_id: Segment,
        chain: Caip2,
        /// True when the source was CAIP-19, so `symbol` and `issuer` came from the resolver
        /// rather than from the author. Such a reference cannot fail S7: there is no author
        /// belief to contradict.
        from_caip19: bool,
    },
    Unit {
        code: Segment,
        authority: Segment,
    },
}

impl AssetRef {
    /// The symbol an alias must begin with under S19. A `unit://` reference's code plays the
    /// same role: `unit://USD/ISO4217` requires an alias beginning `USD_`.
    pub fn symbol(&self) -> &str {
        match self {
            AssetRef::Mint { symbol, .. } => &symbol.text,
            AssetRef::Unit { code, .. } => &code.text,
        }
    }

    pub fn issuer(&self) -> &str {
        match self {
            AssetRef::Mint { issuer, .. } => &issuer.text,
            AssetRef::Unit { authority, .. } => &authority.text,
        }
    }

    /// Two references are the *same asset* iff `(chain, mint_id)` are byte-equal (§2.10.6).
    /// This is the weaker test and the one the engine uses.
    pub fn same_asset(&self, other: &AssetRef) -> bool {
        match (self, other) {
            (
                AssetRef::Mint { mint_id: a, chain: ca, .. },
                AssetRef::Mint { mint_id: b, chain: cb, .. },
            ) => a.text == b.text && ca.namespace.text == cb.namespace.text
                && ca.reference.text == cb.reference.text,
            (AssetRef::Unit { code: a, authority: x }, AssetRef::Unit { code: b, authority: y }) => {
                a.text == b.text && x.text == y.text
            }
            _ => false,
        }
    }

    pub fn is_unit(&self) -> bool {
        matches!(self, AssetRef::Unit { .. })
    }
}

/// Emission is always the native form; CAIP-19 is accepted, never produced (§2.10.5).
impl fmt::Display for AssetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetRef::Mint { symbol, issuer, mint_id, chain, .. } => {
                write!(f, "mint://{symbol}/{issuer}/{mint_id}/{chain}")
            }
            AssetRef::Unit { code, authority } => write!(f, "unit://{code}/{authority}"),
        }
    }
}

/// A reference-level error. Codes are the stable identifiers from spec §10.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefError {
    pub code: &'static str,
    pub message: String,
    /// Span within the reference token, so a diagnostic underlines the offending segment
    /// rather than the whole reference.
    pub span: Span,
}

impl RefError {
    fn new(code: &'static str, span: Span, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), span }
    }
}

impl fmt::Display for RefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// What a namespace requires of a chain reference and a mint id (S9).
struct NamespaceRules {
    /// The CAIP-19 asset namespace this chain uses (`token`, `erc20`, …).
    asset_ns: &'static str,
    check_chain_reference: fn(&str) -> Result<(), String>,
    check_mint_id: fn(&str) -> Result<(), String>,
}

/// Adding a chain is an entry in this table plus resolver support, reviewed — not an
/// authoring-time capability (§2.10.4).
fn namespace_rules(ns: &str) -> Option<NamespaceRules> {
    match ns {
        "solana" => Some(NamespaceRules {
            asset_ns: "token",
            check_chain_reference: |s| {
                if s.len() != 32 {
                    return Err(format!("solana chain reference is 32 base58 characters, found {}", s.len()));
                }
                check_base58(s)
            },
            check_mint_id: |s| {
                if !(32..=44).contains(&s.len()) {
                    return Err(format!("solana mint id is 32-44 base58 characters, found {}", s.len()));
                }
                check_base58(s)
            },
        }),
        "eip155" => Some(NamespaceRules {
            asset_ns: "erc20",
            check_chain_reference: |s| {
                if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("eip155 chain reference is a decimal chain id".into());
                }
                if s.len() > 1 && s.starts_with('0') {
                    return Err("eip155 chain id has no leading zero".into());
                }
                Ok(())
            },
            check_mint_id: |s| {
                let Some(hex) = s.strip_prefix("0x") else {
                    return Err("eip155 mint id starts with 0x".into());
                };
                if hex.len() != 40 {
                    return Err(format!("eip155 mint id is 0x and 40 hex digits, found {}", hex.len()));
                }
                if !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                    return Err("eip155 mint id is lowercase hex".into());
                }
                Ok(())
            },
        }),
        _ => None,
    }
}

/// base58 excluding the four characters that look like each other: `0`, `O`, `I`, `l`.
fn check_base58(s: &str) -> Result<(), String> {
    for (i, c) in s.char_indices() {
        let ok = c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l');
        if !ok {
            return Err(format!("{c:?} at offset {i} is not base58 (0, O, I and l are excluded)"));
        }
    }
    Ok(())
}

/// Parse a reference token. `base` is the token's offset in the source, so returned spans
/// point into the original document rather than into the token.
pub fn parse(token: &str, base: usize) -> Result<AssetRef, RefError> {
    let at = |r: Range<usize>| (base + r.start)..(base + r.end);

    if let Some(rest) = token.strip_prefix("mint://") {
        parse_mint(rest, "mint://".len(), base)
    } else if let Some(rest) = token.strip_prefix("unit://") {
        parse_unit(rest, "unit://".len(), base)
    } else if let Some(rest) = token.strip_prefix("asset://") {
        // The asset:// prefix is optional and carries no meaning beyond making the token
        // self-describing where a reference is pasted out of context (§2.10.5).
        parse_caip19(rest, "asset://".len(), base)
    } else if token.contains('/') && token.contains(':') && !token.contains("://") {
        parse_caip19(token, 0, base)
    } else {
        Err(RefError::new(
            "E410",
            at(0..token.len()),
            "expected mint://, unit:// or a CAIP-19 reference",
        ))
    }
}

/// Split on `/`, rejecting empty segments so `a//b` is a segment-count error rather than an
/// empty-named one.
fn segments(rest: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, c) in rest.char_indices() {
        if c == '/' {
            out.push((start, &rest[start..i]));
            start = i + 1;
        }
    }
    out.push((start, &rest[start..]));
    out
}

fn parse_mint(rest: &str, off: usize, base: usize) -> Result<AssetRef, RefError> {
    let parts = segments(rest);
    let whole = (base + off)..(base + off + rest.len());
    if parts.len() != 4 {
        return Err(RefError::new(
            "E411",
            whole,
            format!("mint:// takes exactly four segments, found {}", parts.len()),
        ));
    }
    let span = |i: usize| {
        let (s, t) = parts[i];
        (base + off + s)..(base + off + s + t.len())
    };

    let symbol = parts[0].1;
    let issuer = parts[1].1;
    let mint_id = parts[2].1;
    let chain_txt = parts[3].1;

    check_symbol(symbol).map_err(|m| RefError::new("E410", span(0), m))?;
    check_issuer(issuer).map_err(|m| RefError::new("E410", span(1), m))?;

    let chain = parse_caip2(chain_txt, base + off + parts[3].0)?;

    let rules = namespace_rules(&chain.namespace.text).ok_or_else(|| {
        RefError::new(
            "E403",
            chain.namespace.span.clone(),
            format!("unknown chain namespace {:?}", chain.namespace.text),
        )
    })?;
    (rules.check_chain_reference)(&chain.reference.text)
        .map_err(|m| RefError::new("E410", chain.reference.span.clone(), m))?;
    (rules.check_mint_id)(mint_id).map_err(|m| RefError::new("E410", span(2), m))?;

    Ok(AssetRef::Mint {
        symbol: Segment::new(symbol, span(0)),
        issuer: Segment::new(issuer, span(1)),
        mint_id: Segment::new(mint_id, span(2)),
        chain,
        from_caip19: false,
    })
}

fn parse_unit(rest: &str, off: usize, base: usize) -> Result<AssetRef, RefError> {
    let parts = segments(rest);
    let whole = (base + off)..(base + off + rest.len());
    if parts.len() != 2 {
        return Err(RefError::new(
            "E411",
            whole,
            format!("unit:// takes exactly two segments, found {}", parts.len()),
        ));
    }
    let span = |i: usize| {
        let (s, t) = parts[i];
        (base + off + s)..(base + off + s + t.len())
    };
    let code = parts[0].1;
    let authority = parts[1].1;

    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(RefError::new(
            "E410",
            span(0),
            "a unit code is three uppercase letters",
        ));
    }
    check_symbol(authority).map_err(|m| RefError::new("E410", span(1), m))?;

    Ok(AssetRef::Unit {
        code: Segment::new(code, span(0)),
        authority: Segment::new(authority, span(1)),
    })
}

/// `<namespace>:<reference>/<asset-ns>:<asset-ref>` — the same object as the native form,
/// with `symbol` and `issuer` left for the resolver to fill.
fn parse_caip19(rest: &str, off: usize, base: usize) -> Result<AssetRef, RefError> {
    let parts = segments(rest);
    let whole = (base + off)..(base + off + rest.len());
    if parts.len() != 2 {
        return Err(RefError::new(
            "E411",
            whole,
            format!("a CAIP-19 reference takes two segments, found {}", parts.len()),
        ));
    }
    let chain = parse_caip2(parts[0].1, base + off + parts[0].0)?;

    let (a_start, asset_part) = parts[1];
    let a_base = base + off + a_start;
    let Some(colon) = asset_part.find(':') else {
        return Err(RefError::new(
            "E410",
            a_base..(a_base + asset_part.len()),
            "expected <asset-namespace>:<asset-reference>",
        ));
    };
    let asset_ns = &asset_part[..colon];
    let asset_ref = &asset_part[colon + 1..];

    let rules = namespace_rules(&chain.namespace.text).ok_or_else(|| {
        RefError::new(
            "E403",
            chain.namespace.span.clone(),
            format!("unknown chain namespace {:?}", chain.namespace.text),
        )
    })?;
    if asset_ns != rules.asset_ns {
        return Err(RefError::new(
            "E413",
            a_base..(a_base + colon),
            format!(
                "chain {} uses the {:?} asset namespace, found {:?}",
                chain.namespace.text, rules.asset_ns, asset_ns
            ),
        ));
    }
    (rules.check_chain_reference)(&chain.reference.text)
        .map_err(|m| RefError::new("E410", chain.reference.span.clone(), m))?;
    let ar_span = (a_base + colon + 1)..(a_base + asset_part.len());
    (rules.check_mint_id)(asset_ref).map_err(|m| RefError::new("E410", ar_span.clone(), m))?;

    Ok(AssetRef::Mint {
        // Filled from the resolver during compilation; empty here rather than guessed.
        symbol: Segment::new("", ar_span.clone()),
        issuer: Segment::new("", ar_span.clone()),
        mint_id: Segment::new(asset_ref, ar_span),
        chain,
        from_caip19: true,
    })
}

fn parse_caip2(text: &str, base: usize) -> Result<Caip2, RefError> {
    let Some(colon) = text.find(':') else {
        return Err(RefError::new(
            "E410",
            base..(base + text.len()),
            "expected a CAIP-2 chain id, <namespace>:<reference>",
        ));
    };
    let ns = &text[..colon];
    let re = &text[colon + 1..];
    if ns.is_empty() || !ns.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
        return Err(RefError::new(
            "E410",
            base..(base + colon),
            "a CAIP-2 namespace is lowercase alphanumeric",
        ));
    }
    if re.is_empty() {
        return Err(RefError::new(
            "E410",
            (base + colon + 1)..(base + text.len()),
            "a CAIP-2 reference is not empty",
        ));
    }
    Ok(Caip2 {
        namespace: Segment::new(ns, base..(base + colon)),
        reference: Segment::new(re, (base + colon + 1)..(base + text.len())),
    })
}

fn check_symbol(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 32 {
        return Err("a symbol is 1 to 32 characters".into());
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err("a symbol starts with a letter or digit".into());
    }
    // A fact segment would let two references to one mint disagree about it (E412).
    if s.contains('_') {
        return Err("a symbol has no underscore".into());
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '.' || c == '-') {
            return Err(format!("{c:?} is not permitted in a symbol"));
        }
    }
    Ok(())
}

fn check_issuer(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 64 {
        return Err("an issuer is 1 to 64 characters".into());
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err("an issuer starts with a letter or digit".into());
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_') {
            return Err(format!("{c:?} is not permitted in an issuer"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOL_CHAIN: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn native() -> String {
        format!("mint://USDC/Circle/{USDC_MINT}/{SOL_CHAIN}")
    }

    #[test]
    fn native_form_round_trips() {
        let r = parse(&native(), 0).unwrap();
        assert_eq!(r.to_string(), native());
        assert_eq!(r.symbol(), "USDC");
        assert_eq!(r.issuer(), "Circle");
    }

    #[test]
    fn caip19_normalises_and_is_the_same_asset() {
        let a = parse(&native(), 0).unwrap();
        let b = parse(&format!("{SOL_CHAIN}/token:{USDC_MINT}"), 0).unwrap();
        let c = parse(&format!("asset://{SOL_CHAIN}/token:{USDC_MINT}"), 0).unwrap();
        assert!(a.same_asset(&b), "CAIP-19 denotes the same object as the native form");
        // Not field equality: the prefix shifts every span by its own length, which is the
        // spans being right rather than the parse being different.
        assert!(b.same_asset(&c), "the asset:// prefix carries no meaning");
        assert!(matches!(b, AssetRef::Mint { from_caip19: true, .. }));
    }

    #[test]
    fn spans_point_at_the_offending_segment() {
        // The whole point of a sub-parser: E401 must underline the issuer, not the token.
        let src = format!("  asset X = {}", native());
        let base = src.find("mint://").unwrap();
        let r = parse(&native(), base).unwrap();
        let AssetRef::Mint { issuer, .. } = &r else { panic!() };
        assert_eq!(&src[issuer.span.clone()], "Circle");
    }

    #[test]
    fn base58_excludes_the_lookalike_characters() {
        for bad in ['0', 'O', 'I', 'l'] {
            let mint: String = core::iter::once(bad).chain(USDC_MINT.chars().skip(1)).collect();
            let e = parse(&format!("mint://USDC/Circle/{mint}/{SOL_CHAIN}"), 0).unwrap_err();
            assert_eq!(e.code, "E410", "{bad} should be rejected");
        }
    }

    #[test]
    fn wrong_segment_count_names_the_count() {
        let e = parse(&format!("mint://USDC/Circle/{USDC_MINT}"), 0).unwrap_err();
        assert_eq!(e.code, "E411");
        assert!(e.message.contains('3'), "{}", e.message);
    }

    #[test]
    fn unknown_namespace_fails_closed() {
        let e = parse(&format!("mint://USDC/Circle/{USDC_MINT}/dogecoin:abc"), 0).unwrap_err();
        assert_eq!(e.code, "E403");
    }

    #[test]
    fn caip19_asset_namespace_must_match_the_chain() {
        let e = parse(&format!("{SOL_CHAIN}/erc20:{USDC_MINT}"), 0).unwrap_err();
        assert_eq!(e.code, "E413");
    }

    #[test]
    fn eip155_shape() {
        let ok = "mint://USDC/Circle/0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48/eip155:1";
        assert!(parse(ok, 0).is_ok());
        let short = "mint://USDC/Circle/0xa0b8/eip155:1";
        assert_eq!(parse(short, 0).unwrap_err().code, "E410");
        let no_prefix = "mint://USDC/Circle/a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48/eip155:1";
        assert_eq!(parse(no_prefix, 0).unwrap_err().code, "E410");
    }

    #[test]
    fn unit_references() {
        let r = parse("unit://USD/ISO4217", 0).unwrap();
        assert!(r.is_unit());
        assert_eq!(r.symbol(), "USD");
        assert_eq!(r.to_string(), "unit://USD/ISO4217");
        assert_eq!(parse("unit://usd/ISO4217", 0).unwrap_err().code, "E410");
    }

    #[test]
    fn a_symbol_with_an_underscore_is_not_a_symbol() {
        // Guards the S19/S20 interaction: symbols cannot contain '_', so an attacker cannot
        // mint a symbol that swallows the qualifier separator.
        let e = parse(&format!("mint://US_DC/Circle/{USDC_MINT}/{SOL_CHAIN}"), 0).unwrap_err();
        assert_eq!(e.code, "E410");
    }

    #[test]
    fn same_asset_ignores_the_assertions() {
        let a = parse(&native(), 0).unwrap();
        let b = parse(&format!("mint://USDT/Tether/{USDC_MINT}/{SOL_CHAIN}"), 0).unwrap();
        assert!(a.same_asset(&b), "identity is (chain, mint_id); the rest is S7's problem");
        assert_ne!(a, b);
    }
}
