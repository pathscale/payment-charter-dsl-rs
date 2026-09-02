//! The resolver, and the rules that need it (S7–S13).
//!
//! Everything here answers one question: **is this asset the one the author believes it is?**
//! `symbol` and `issuer` are assertions the author wrote down, and S7 checks them segment by
//! segment against a curated record. That is what makes the redundancy in a reference worth
//! its length — a bare address can only be wrong silently.
//!
//! These checks are separated from `rules.rs` because they need data the text does not carry.
//! An approximate S7 would be worse than an absent one: it would pass documents the engine
//! must refuse.

use crate::ast::{Charter, Decl};
use crate::diag::Diagnostic;
use crate::json::Json;
use charter_assetref::AssetRef;
use std::collections::HashMap;

/// A resolver record for a mint. Carried verbatim into the compiled form's `resolved_assets`
/// (§9), so evaluation performs no lookup.
#[derive(Clone, Debug)]
pub struct MintRecord {
    pub chain: String,
    pub mint_id: String,
    pub symbol: String,
    /// From the resolver's curation, **never** from on-chain metadata (S10). Metadata is
    /// self-asserted, so an issuer copied from it is worthless as a discriminator — and the
    /// issuer segment is what separates native from bridged.
    pub issuer: String,
    /// The sole authority for money conversion (§2.6).
    pub decimals: u8,
    pub class: String,
    pub token_program: String,
    pub status: Status,
    pub since_version: u64,
}

#[derive(Clone, Debug)]
pub struct UnitRecord {
    pub code: String,
    pub authority: String,
    pub decimals: u8,
    /// S11: a `unit://` limit must declare a rate source and a staleness bound, and must deny
    /// when the rate is stale. An empty list means there is no source to be stale.
    pub rate_sources: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Active,
    /// A revoked mint always stops the charters that name it (E406). Revocation is the
    /// mechanism for "this turned out to be something else", so it must not be absorbed
    /// quietly.
    Revoked,
}

#[derive(Clone, Debug, Default)]
pub struct Resolver {
    pub tier: String,
    pub version: u64,
    mints: HashMap<(String, String), MintRecord>,
    units: HashMap<(String, String), UnitRecord>,
    /// Test-only escape hatch: report this scale for anything not in the tables. Never set in
    /// production, where an assumed scale is a wrong payment by a factor of ten.
    uniform_decimals: Option<u8>,
}

impl Resolver {
    /// A resolver that reports the same scale for every asset and verifies nothing. For
    /// fixtures whose subject is not the resolver; the name says so at every call site.
    pub fn uniform(decimals: u8) -> Self {
        Self { uniform_decimals: Some(decimals), ..Default::default() }
    }

    pub fn from_json(src: &str) -> Result<Self, String> {
        let v = crate::json::parse(src);
        let mut r = Resolver {
            tier: v.str("tier").unwrap_or("common").to_string(),
            version: v.num("version").unwrap_or(0.0) as u64,
            ..Default::default()
        };
        for m in v.arr("mints").unwrap_or(&[]) {
            let rec = MintRecord {
                chain: m.str("chain").ok_or("mint has no chain")?.to_string(),
                mint_id: m.str("mint_id").ok_or("mint has no mint_id")?.to_string(),
                symbol: m.str("symbol").ok_or("mint has no symbol")?.to_string(),
                issuer: m.str("issuer").ok_or("mint has no issuer")?.to_string(),
                decimals: m.num("decimals").ok_or("mint has no decimals")? as u8,
                class: m.str("class").unwrap_or("").to_string(),
                token_program: m.str("token_program").unwrap_or("").to_string(),
                status: match m.str("status") {
                    Some("revoked") => Status::Revoked,
                    _ => Status::Active,
                },
                since_version: m.num("since_version").unwrap_or(0.0) as u64,
            };
            r.mints.insert((rec.chain.clone(), rec.mint_id.clone()), rec);
        }
        for u in v.arr("units").unwrap_or(&[]) {
            let rec = UnitRecord {
                code: u.str("code").ok_or("unit has no code")?.to_string(),
                authority: u.str("authority").ok_or("unit has no authority")?.to_string(),
                decimals: u.num("decimals").ok_or("unit has no decimals")? as u8,
                rate_sources: u
                    .arr("rate_sources")
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|j| match j {
                        Json::Str(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect(),
            };
            r.units.insert((rec.code.clone(), rec.authority.clone()), rec);
        }
        Ok(r)
    }

    pub fn mint(&self, chain: &str, mint_id: &str) -> Option<&MintRecord> {
        self.mints.get(&(chain.to_string(), mint_id.to_string()))
    }

    pub fn unit(&self, code: &str, authority: &str) -> Option<&UnitRecord> {
        self.units.get(&(code.to_string(), authority.to_string()))
    }

    /// The scale for a declared asset name, after [`check`] has run.
    pub fn decimals_for(&self, r: &AssetRef) -> Option<u8> {
        if let Some(d) = self.uniform_decimals {
            return Some(d);
        }
        match r {
            AssetRef::Mint { mint_id, chain, .. } => {
                self.mint(&chain.to_string(), &mint_id.text).map(|m| m.decimals)
            }
            AssetRef::Unit { code, authority } => {
                self.unit(&code.text, &authority.text).map(|u| u.decimals)
            }
        }
    }

    fn verifies(&self) -> bool {
        self.uniform_decimals.is_none()
    }
}

/// S7–S13 and the resolver-dependent literal checks, over a whole document.
pub fn check(c: &Charter, r: &Resolver) -> Vec<Diagnostic> {
    let mut d = Vec::new();
    if !r.verifies() {
        // A uniform resolver states plainly that it verifies nothing, rather than silently
        // passing every reference.
        return d;
    }

    // S12: evaluating under a version later than the pin is permitted only if every asset the
    // document names still resolves identically. Earlier than the pin is not evaluation under
    // a later version — it is a resolver that does not yet know what the author saw.
    if r.version < c.resolver_version {
        d.push(Diagnostic::error(
            "E405",
            format!(
                "this charter pins resolver version {}, and the resolver offered is {} (S12)",
                c.resolver_version, r.version
            ),
            c.resolver_tier.span.clone(),
        ));
    }

    for decl in &c.decls {
        let Decl::Asset(a) = decl else { continue };
        match &a.reference.node {
            AssetRef::Mint { symbol, issuer, mint_id, chain, from_caip19 } => {
                let Some(rec) = r.mint(&chain.to_string(), &mint_id.text) else {
                    // "Never seen" and "fine" must not produce the same outcome.
                    d.push(Diagnostic::error(
                        "E402",
                        format!(
                            "no record for {} on {}. An unknown mint fails closed (S7).",
                            mint_id.text, chain
                        ),
                        mint_id.span.clone(),
                    ));
                    continue;
                };

                if rec.status == Status::Revoked {
                    d.push(Diagnostic::error(
                        "E406",
                        format!(
                            "`{}` is revoked as of resolver version {} (S12). Revocation is how \
                             the resolver says \"this turned out to be something else\", so it \
                             is not absorbed quietly.",
                            a.name.node, rec.since_version
                        ),
                        a.reference.span.clone(),
                    ));
                }

                // S7 names the disagreeing segment, which is the whole reason the reference is
                // parsed rather than split: the diagnostic underlines the issuer inside the
                // reference rather than the whole token.
                if !*from_caip19 {
                    if symbol.text != rec.symbol {
                        d.push(Diagnostic::error(
                            "E401",
                            format!(
                                "the resolver records this mint's symbol as `{}`, not `{}` (S7)",
                                rec.symbol, symbol.text
                            ),
                            symbol.span.clone(),
                        ));
                    }
                    if issuer.text != rec.issuer {
                        d.push(Diagnostic::error(
                            "E401",
                            format!(
                                "the resolver records this mint's issuer as `{}`, not `{}` (S7). \
                                 The issuer segment is what separates native from bridged.",
                                rec.issuer, issuer.text
                            ),
                            issuer.span.clone(),
                        ));
                    }
                }

                decimals_cap(&a.name.node, rec.decimals, &a.reference.span, &mut d);
            }
            AssetRef::Unit { code, authority } => {
                let Some(rec) = r.unit(&code.text, &authority.text) else {
                    d.push(Diagnostic::error(
                        "E402",
                        format!("no record for unit://{}/{} (S7)", code.text, authority.text),
                        a.reference.span.clone(),
                    ));
                    continue;
                };
                // S11: a unit limit must have a rate source, or there is nothing to be stale
                // and nothing to convert conservatively.
                if rec.rate_sources.is_empty() && used_for_money(c, &a.name.node) {
                    d.push(Diagnostic::error(
                        "E404",
                        format!(
                            "`{}` has no rate source, so a limit over it cannot convert or \
                             detect staleness (S11). A unit limit must deny when the rate is \
                             stale, which requires there to be a rate.",
                            a.name.node
                        ),
                        a.reference.span.clone(),
                    ));
                }
                decimals_cap(&a.name.node, rec.decimals, &a.reference.span, &mut d);
            }
        }
    }
    d
}

fn decimals_cap(name: &str, decimals: u8, span: &crate::lex::Span, d: &mut Vec<Diagnostic>) {
    if decimals > 9 {
        d.push(Diagnostic::error(
            "E223",
            format!(
                "the resolver reports {decimals} decimals for `{name}`. More than nine is not \
                 usable (§2.6): it is what keeps money inside u64, where an eighteen-decimal \
                 asset tops out at 18.44 tokens. Refused rather than truncated, because E202 \
                 already says a literal that cannot be represented exactly is an error and \
                 never a rounding."
            ),
            span.clone(),
        ));
    }
}

fn used_for_money(c: &Charter, asset: &str) -> bool {
    c.decls.iter().any(|d| match d {
        Decl::Limit(l) => match &l.dimension {
            crate::ast::Dimension::Amount { base, .. } => base.node.asset.node == asset,
            _ => false,
        },
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMON: &str = include_str!("../../../../payment-charter-dsl/resolver/common-41.json");

    fn resolver() -> Resolver {
        Resolver::from_json(COMMON).expect("the common tier parses")
    }

    fn charter_with(asset_line: &str) -> String {
        format!(
            "charter t version 1\nresolver common@41\ntimezone UTC\n\n  {asset_line}\n\n  \
             limit spend\n    amount 100.00 X\n    per fixed day\n"
        )
    }

    fn check_src(src: &str) -> Vec<Diagnostic> {
        let ast = crate::parse(src).expect("parses");
        check(&ast, &resolver())
    }

    fn codes(d: &[Diagnostic]) -> Vec<&str> {
        d.iter().map(|x| x.code).collect()
    }

    #[test]
    fn the_common_tier_loads() {
        let r = resolver();
        assert_eq!(r.version, 41);
        assert!(r
            .mint(
                "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
            )
            .is_some());
    }

    #[test]
    fn a_correct_reference_passes() {
        let src = charter_with("asset USDC_circle = mint://USDC/Circle/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
            .replace("100.00 X", "100.00 USDC_circle");
        assert!(codes(&check_src(&src)).is_empty(), "{:?}", check_src(&src));
    }

    #[test]
    fn a_lying_symbol_is_caught_and_the_segment_named() {
        // This is the S19 attack seen from the other side: the alias is honest about the
        // reference, and the reference is dishonest about the mint.
        let src = charter_with("asset USDT_circle = mint://USDT/Circle/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
            .replace("100.00 X", "100.00 USDT_circle");
        let d = check_src(&src);
        assert_eq!(codes(&d), vec!["E401"]);
        assert!(d[0].message.contains("USDC"), "{}", d[0].message);
    }

    #[test]
    fn a_bridged_issuer_on_a_native_mint_is_caught() {
        let src = charter_with("asset USDC_wormhole = mint://USDC/Wormhole/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
            .replace("100.00 X", "100.00 USDC_wormhole");
        let d = check_src(&src);
        assert_eq!(codes(&d), vec!["E401"]);
        assert!(d[0].message.contains("native from bridged"), "{}", d[0].message);
    }

    #[test]
    fn an_unknown_mint_fails_closed() {
        let src = charter_with("asset USDC_unknown = mint://USDC/Circle/9zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
            .replace("100.00 X", "100.00 USDC_unknown");
        assert_eq!(codes(&check_src(&src)), vec!["E402"]);
    }

    #[test]
    fn a_revoked_mint_stops_the_charter() {
        let src = charter_with("asset STSOL_lido = mint://STSOL/Lido/7dHbWXmci3dT8UFYWYZweBLXgycu7Y3iL6trKn1Y7ARj/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
            .replace("100.00 X", "100.00 STSOL_lido");
        assert_eq!(codes(&check_src(&src)), vec!["E406"]);
    }

    #[test]
    fn eighteen_decimals_is_refused() {
        let src = charter_with("asset DAI_maker = mint://DAI/MakerDAO/0x6b175474e89094c44da98b954eedeac495271d0f/eip155:1")
            .replace("100.00 X", "100.00 DAI_maker");
        let d = check_src(&src);
        assert_eq!(codes(&d), vec!["E223"]);
        assert!(d[0].message.contains("18.44 tokens"), "{}", d[0].message);
    }

    #[test]
    fn a_devnet_reference_does_not_resolve_as_mainnet() {
        // The genesis identity differs, so a devnet charter fails on mainnet and vice versa.
        // That is what makes rehearsal structurally safe rather than merely conventional.
        let src = charter_with("asset USDC_circle = mint://USDC/Circle/4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
            .replace("100.00 X", "100.00 USDC_circle");
        assert_eq!(codes(&check_src(&src)), vec!["E402"]);
    }

    #[test]
    fn caip19_cannot_fail_s7() {
        // There is no author belief to contradict: symbol and issuer come from the resolver.
        let src = charter_with("asset USDC_circle = asset://solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/token:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
            .replace("100.00 X", "100.00 USDC_circle");
        assert!(codes(&check_src(&src)).is_empty());
    }

    #[test]
    fn a_unit_limit_without_a_rate_source_is_refused() {
        let src = charter_with("asset USD_iso4217 = unit://USD/ISO4217")
            .replace("100.00 X", "100.00 USD_iso4217");
        assert_eq!(codes(&check_src(&src)), vec!["E404"]);
    }

    #[test]
    fn a_pin_the_resolver_cannot_satisfy_is_refused() {
        let src = charter_with("asset USDC_circle = mint://USDC/Circle/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
            .replace("100.00 X", "100.00 USDC_circle")
            .replace("resolver common@41", "resolver common@99");
        assert_eq!(codes(&check_src(&src)), vec!["E405"]);
    }

    #[test]
    fn a_uniform_resolver_says_it_verifies_nothing() {
        let ast = crate::parse(&charter_with("asset USDT_circle = mint://USDT/Circle/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp").replace("100.00 X", "100.00 USDT_circle")).unwrap();
        assert!(
            check(&ast, &Resolver::uniform(6)).is_empty(),
            "a uniform resolver verifies nothing, and the name is the warning"
        );
    }
}
