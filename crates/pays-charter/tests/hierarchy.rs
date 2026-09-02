//! Runs `conformance/hierarchy/*.json` from the shared corpus — §8A, H1 through H6.
//!
//! A hierarchy vector names a chain root first rather than a single charter, and may swap the
//! chain mid-run to a sibling leaf. That is what makes H2 testable at all: a company-wide
//! ceiling is only observably company-wide when a second agent is refused by a meter the first
//! one moved.
//!
//! Vectors with `expect_link` assert that the chain is refused at link time. Those are the ones
//! that matter most for an author, because they are the findings that arrive while the document
//! is still in an editor rather than when a payment is refused six weeks later.

use pays_charter::link::{link, Level};
use pays_charter::{compile, Resolver};
use pays_policy::{Engine, Ledger, Outcome, Request};
use std::path::{Path, PathBuf};

#[path = "json.rs"]
mod json;
use json::parse as parse_json;
use json::Json;

const DECIMALS: u8 = 2;

fn corpus() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CHARTER_CORPUS") {
        let p = PathBuf::from(p);
        return p.is_dir().then_some(p);
    }
    let sibling =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../payment-charter-dsl/conformance");
    sibling.is_dir().then(|| sibling.canonicalize().unwrap())
}

fn minor_units(s: &str, decimals: u8) -> u64 {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    assert!(frac.len() <= decimals as usize, "{s} exceeds {decimals} decimals");
    let mut padded = frac.to_string();
    while padded.len() < decimals as usize {
        padded.push('0');
    }
    let f: u64 = if padded.is_empty() { 0 } else { padded.parse().unwrap() };
    whole.parse::<u64>().unwrap() * 10u64.pow(decimals as u32) + f
}

/// A parsed and compiled level, kept alive for as long as the chain that borrows it.
struct Doc {
    ast: pays_charter::ast::Charter,
    compiled: pays_policy::compiled::Compiled,
}

fn load(root: &Path, rel: &str) -> Result<Doc, String> {
    let path = root.join(rel);
    let src = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let ast = pays_charter::parse(&src).map_err(|e| format!("{rel}: {}", e[0].render(&src)))?;
    let compiled = compile(&ast, &Resolver::uniform(DECIMALS))
        .map_err(|e| format!("{rel}: {}", e[0].render(&src)))?;
    Ok(Doc { ast, compiled })
}

fn load_chain(root: &Path, names: &[Json]) -> Result<Vec<Doc>, String> {
    let mut out = Vec::new();
    for n in names {
        let Json::Str(rel) = n else { return Err("a chain names charter paths".into()) };
        out.push(load(root, rel)?);
    }
    Ok(out)
}

struct VectorResult {
    name: String,
    failures: Vec<String>,
}

fn run_vector(root: &Path, path: &Path) -> VectorResult {
    let raw = std::fs::read_to_string(path).unwrap();
    let v = parse_json(&raw);
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let mut failures = Vec::new();

    let Some(names) = v.arr("chain") else {
        return VectorResult { name, failures: vec!["vector names no chain".into()] };
    };
    let mut docs = match load_chain(root, names) {
        Ok(d) => d,
        Err(e) => return VectorResult { name, failures: vec![e] },
    };

    let levels: Vec<Level> = docs.iter().map(|d| Level::new(&d.ast, &d.compiled)).collect();
    let linked = link(&levels);

    // A vector may assert that the chain does not link at all. That is a complete assertion:
    // nothing downstream of a refused link is meaningful, so the vector ends here.
    if let Some(want) = v.str("expect_link") {
        match &linked {
            Ok(_) => failures.push(format!("expected the chain to be refused with {want}; it linked")),
            Err(ds) => {
                if !ds.iter().any(|d| d.code == want) {
                    failures.push(format!(
                        "expected {want}, got {:?}",
                        ds.iter().map(|d| d.code).collect::<Vec<_>>()
                    ));
                }
            }
        }
        return VectorResult { name, failures };
    }

    let (mut chain, warnings) = match linked {
        Ok(x) => x,
        Err(ds) => {
            let src = std::fs::read_to_string(root.join(match &names[names.len() - 1] {
                Json::Str(s) => s.clone(),
                _ => String::new(),
            }))
            .unwrap_or_default();
            failures.push(format!("chain did not link: {}", ds[0].render(&src)));
            return VectorResult { name, failures };
        }
    };

    if let Some(want) = v.str("expect_warning") {
        if !warnings.iter().any(|w| w.code == want) {
            failures.push(format!(
                "expected warning {want}, got {:?}",
                warnings.iter().map(|w| w.code).collect::<Vec<_>>()
            ));
        }
    }

    let mut ledger = Ledger::new();
    let mut clock = v.num("clock").unwrap_or(0.0) as i64;

    for (n, step) in v.arr("requests").unwrap_or(&[]).iter().enumerate() {
        if let Some(at) = step.num("at") {
            clock = at as i64;
        }

        // Swapping the chain is not installing a new version: it is a different agent, under
        // the same department, against the same ledger. The department's accumulator is keyed
        // by the department's own charter id, so it is the same meter for both — which is the
        // property H2 is claiming and the reason this step exists.
        if let Some(next) = step.arr("chain") {
            match load_chain(root, next) {
                Ok(d) => {
                    docs = d;
                    let levels: Vec<Level> =
                        docs.iter().map(|x| Level::new(&x.ast, &x.compiled)).collect();
                    match link(&levels) {
                        Ok((c, _)) => chain = c,
                        Err(ds) => {
                            failures.push(format!("request {n}: chain did not link: {}", ds[0]));
                            return VectorResult { name, failures };
                        }
                    }
                }
                Err(e) => {
                    failures.push(format!("request {n}: {e}"));
                    return VectorResult { name, failures };
                }
            }
            continue;
        }

        let Some(expect) = step.str("expect") else { continue };

        let tagged = step.str("category");
        let plane = step
            .str("provenance")
            .and_then(pays_policy::Plane::parse)
            .unwrap_or(pays_policy::Plane::Principal);

        let req = Request {
            at: clock,
            amount: minor_units(step.str("amount").unwrap_or("0"), DECIMALS),
            asset: step.str("asset").unwrap_or("").to_string(),
            instrument: step.str("instrument").map(str::to_string),
            counterparty: step.str("counterparty").map(str::to_string),
            mcc: tagged.filter(|t| t.starts_with("mcc:")).map(str::to_string),
            country: tagged.filter(|t| t.starts_with("country:")).map(str::to_string),
            agent: step.str("agent").map(str::to_string),
            account: step.str("account").map(str::to_string),
            provenance: pays_policy::eval::Provenance {
                recipient: plane,
                amount: plane,
                asset: plane,
                venue: plane,
            },
            // §2.8: the local calendar date, in the leaf's offset. Every level in a chain
            // resolves its own windows, but there is one request and one date on it.
            date: (clock + chain.leaf().timezone_offset as i64).div_euclid(86400) as i32,
            ..Default::default()
        };

        let engine = Engine::chained(&chain);
        let decision = engine.decide(&mut ledger, &req);
        let got = match &decision.outcome {
            Outcome::Allow => "allow",
            Outcome::Escalate { .. } => "escalate",
            Outcome::Deny { .. } => "deny",
        };
        if got != expect {
            failures.push(format!(
                "request {n} ({}): expected {expect}, got {got} — {:?}",
                step.str("note").unwrap_or(""),
                decision.outcome
            ));
            continue;
        }

        // H1's number, which H4 requires an interface to show. Asserting it separately from the
        // outcome is the point: a vector that only checked allow/deny would pass with the
        // ceiling computed wrongly, right up until someone displayed it.
        if let Some(want) = step.str("effective_ceiling") {
            let want = minor_units(want, DECIMALS);
            if decision.effective_ceiling != Some(want) {
                failures.push(format!(
                    "request {n}: effective ceiling {:?}, expected {want}",
                    decision.effective_ceiling
                ));
            }
        }

        if let Outcome::Deny { by, code } = &decision.outcome {
            if let Some(want) = step.str("code") {
                if want != *code {
                    failures.push(format!("request {n}: denied with {code}, expected {want}"));
                }
            }
            if let Some(want) = step.arr("denied_by") {
                let want: Vec<String> = want
                    .iter()
                    .filter_map(|j| match j {
                        Json::Str(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect();
                if !want.is_empty() && !want.iter().all(|w| by.contains(w)) {
                    failures.push(format!("request {n}: denied by {by:?}, expected {want:?}"));
                }
            }
        }

        if let (Outcome::Escalate { level, limit, trigger, approvers, quorum, .. }, Some(e)) =
            (&decision.outcome, step.get("escalation"))
        {
            let mut want = |field: &str, got: &str| {
                if let Some(w) = e.str(field) {
                    if w != got {
                        failures.push(format!(
                            "request {n}: escalation {field} is {got:?}, expected {w:?}"
                        ));
                    }
                }
            };
            want("level", level);
            want("limit", limit);
            want("trigger", trigger);
            want("approvers", approvers);
            if let Some(q) = e.num("quorum") {
                if q as u64 != *quorum {
                    failures.push(format!("request {n}: quorum {quorum}, expected {q}"));
                }
            }
        }

        if let Err(e) = pays_policy::check_invariant_chain(&chain, &ledger) {
            failures.push(format!("request {n}: invariant violated: {e}"));
        }
    }

    VectorResult { name, failures }
}

#[test]
fn hierarchy_vectors() {
    let Some(root) = corpus() else {
        eprintln!("corpus not found; skipping");
        return;
    };
    let dir = root.join("hierarchy");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no hierarchy vectors found in {}", dir.display());

    let mut failed = Vec::new();
    for f in &files {
        let r = run_vector(&root, f);
        if r.failures.is_empty() {
            eprintln!("  ok   {}", r.name);
        } else {
            eprintln!("  FAIL {}", r.name);
            for x in &r.failures {
                eprintln!("         {x}");
            }
            failed.push(r.name);
        }
    }
    assert!(failed.is_empty(), "{} of {} vectors failed: {failed:?}", failed.len(), files.len());
}
