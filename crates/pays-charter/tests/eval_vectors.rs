//! Runs `conformance/eval/*.json` from the shared corpus.
//!
//! These vectors encode the semantics the specification argues for — the `at least` boundary,
//! exhaustion as a separate question from amount, a prohibition costing nothing, one meter
//! across chains, and §8.4A's rule that an edit changes the ceiling and never the meter. Until
//! this file existed they were prose with a `.json` extension.
//!
//! The JSON reader below is deliberately small and local. `pays-charter` may take
//! dependencies, but a test-only reader for a format this constrained is less to justify than
//! a dependency, and it keeps the suite runnable with no network.

use pays_charter::{compile, Resolver};
use pays_policy::{Engine, Ledger, Outcome, Request};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------- minimal JSON

#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(k),
            _ => None,
        }
    }
    fn str(&self, k: &str) -> Option<&str> {
        match self.get(k) {
            Some(Json::Str(s)) => Some(s),
            _ => None,
        }
    }
    fn num(&self, k: &str) -> Option<f64> {
        match self.get(k) {
            Some(Json::Num(n)) => Some(*n),
            _ => None,
        }
    }
    fn arr(&self, k: &str) -> Option<&[Json]> {
        match self.get(k) {
            Some(Json::Arr(v)) => Some(v),
            _ => None,
        }
    }
}

fn parse_json(s: &str) -> Json {
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    let v = value(&b, &mut i);
    v
}

fn skip_ws(b: &[char], i: &mut usize) {
    while *i < b.len() && b[*i].is_whitespace() {
        *i += 1;
    }
}

fn value(b: &[char], i: &mut usize) -> Json {
    skip_ws(b, i);
    match b.get(*i) {
        Some('{') => {
            *i += 1;
            let mut m = BTreeMap::new();
            loop {
                skip_ws(b, i);
                if b.get(*i) == Some(&'}') {
                    *i += 1;
                    break;
                }
                let Json::Str(k) = value(b, i) else { panic!("object key") };
                skip_ws(b, i);
                assert_eq!(b.get(*i), Some(&':'), "expected ':'");
                *i += 1;
                m.insert(k, value(b, i));
                skip_ws(b, i);
                if b.get(*i) == Some(&',') {
                    *i += 1;
                }
            }
            Json::Obj(m)
        }
        Some('[') => {
            *i += 1;
            let mut v = Vec::new();
            loop {
                skip_ws(b, i);
                if b.get(*i) == Some(&']') {
                    *i += 1;
                    break;
                }
                v.push(value(b, i));
                skip_ws(b, i);
                if b.get(*i) == Some(&',') {
                    *i += 1;
                }
            }
            Json::Arr(v)
        }
        Some('"') => {
            *i += 1;
            let mut s = String::new();
            while let Some(&c) = b.get(*i) {
                *i += 1;
                match c {
                    '"' => break,
                    '\\' => {
                        let e = b[*i];
                        *i += 1;
                        s.push(match e {
                            'n' => '\n',
                            't' => '\t',
                            other => other,
                        });
                    }
                    _ => s.push(c),
                }
            }
            Json::Str(s)
        }
        Some('t') => {
            *i += 4;
            Json::Bool(true)
        }
        Some('f') => {
            *i += 5;
            Json::Bool(false)
        }
        Some('n') => {
            *i += 4;
            Json::Null
        }
        _ => {
            let start = *i;
            while matches!(b.get(*i), Some(c) if c.is_ascii_digit() || *c == '-' || *c == '+' || *c == '.' || *c == 'e' || *c == 'E')
            {
                *i += 1;
            }
            let text: String = b[start..*i].iter().collect();
            Json::Num(text.parse().unwrap_or_else(|_| panic!("number: {text:?}")))
        }
    }
}

// ---------------------------------------------------------------- the harness

fn corpus() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CHARTER_CORPUS") {
        let p = PathBuf::from(p);
        return p.is_dir().then_some(p);
    }
    let sibling =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../payment-charter-dsl/conformance");
    sibling.is_dir().then(|| sibling.canonicalize().unwrap())
}

/// Money in a vector is a decimal string (§1.1), so it is scaled the same way the compiler
/// scales a literal — no float ever touches an amount.
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

const DECIMALS: u8 = 2;

struct VectorResult {
    name: String,
    failures: Vec<String>,
}

fn run_vector(root: &Path, path: &Path) -> VectorResult {
    let raw = std::fs::read_to_string(path).unwrap();
    let v = parse_json(&raw);
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let mut failures = Vec::new();

    let charter_path = root.join(v.str("charter").expect("vector names a charter"));
    let src = std::fs::read_to_string(&charter_path)
        .unwrap_or_else(|e| panic!("{}: {e}", charter_path.display()));

    let ast = match pays_charter::parse(&src) {
        Ok(a) => a,
        Err(e) => {
            failures.push(format!("charter did not parse: {:?}", e[0].render(&src)));
            return VectorResult { name, failures };
        }
    };
    let compiled = match compile(&ast, &Resolver::uniform(DECIMALS)) {
        Ok(c) => c,
        Err(e) => {
            failures.push(format!("charter did not compile: {}", e[0].render(&src)));
            return VectorResult { name, failures };
        }
    };

    let mut compiled = compiled;
    let mut retired: Vec<pays_policy::compiled::Limit> = Vec::new();
    let mut ledger = Ledger::new();
    let mut clock = v.num("clock").unwrap_or(0.0) as i64;

    for (n, step) in v.arr("requests").unwrap_or(&[]).iter().enumerate() {
        if let Some(at) = step.num("at") {
            clock = at as i64;
        }

        // An `install` replaces the charter mid-run, naming a real successor document rather
        // than describing an edit. §8.4A's accumulators are keyed by the wall-clock window and
        // not by the charter version, so installing touches no ledger entry — which is exactly
        // the property these vectors exist to check.
        if let Some(next) = step.str("install") {
            let nsrc = std::fs::read_to_string(root.join(next)).unwrap();
            let nast = match pays_charter::parse(&nsrc) {
                Ok(a) => a,
                Err(e) => {
                    failures.push(format!("successor did not parse: {}", e[0].render(&nsrc)));
                    return VectorResult { name, failures };
                }
            };
            let ncompiled = match compile(&nast, &Resolver::uniform(DECIMALS)) {
                Ok(c) => c,
                Err(e) => {
                    failures.push(format!("successor did not compile: {}", e[0].render(&nsrc)));
                    return VectorResult { name, failures };
                }
            };
            // §8.4A.2: a limit present in version n and absent in n+1 is not deleted. It stops
            // accruing new authority and keeps denying against what it already accumulated
            // until its final window closes — which is what stops a rename being a reset.
            for old in &compiled.limits {
                if !ncompiled.limits.iter().any(|l| l.id == old.id) {
                    retired.push(old.clone());
                }
            }
            compiled = ncompiled;
            continue;
        }

        // §8.1.5 is a state transition on a pending reservation, not a new request: when no
        // approver answers within the escalation's `within`, the reservation is released and
        // the request it was holding is denied.
        if step.get("expire") == Some(&Json::Bool(true)) {
            let released = ledger.expire_pending(clock);
            if released.is_empty() {
                failures.push(format!(
                    "request {n}: expected a pending approval to expire at {clock}, none did"
                ));
            }
            continue;
        }

        let Some(expect) = step.str("expect") else { continue };

        // A tagged literal names exactly one field (§2.11), so route it by its tag rather
        // than setting both and letting a country match a category.
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
            // A vector's `provenance` sets every field, so bare `provenance` — the maximum
            // over the four (§6.1) — is that plane.
            provenance: pays_policy::eval::Provenance {
                recipient: plane,
                amount: plane,
                asset: plane,
                venue: plane,
            },
            date: (clock.div_euclid(86400)) as i32,
            ..Default::default()
        };

        let engine = Engine::with_retired(&compiled, &retired);
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

        // A vector asserting *which* rule refused is asserting the identity of the refusal,
        // which is the point of the corpus: a test passing because the wrong rule fired is
        // worse than no test.
        if let (Outcome::Deny { by, .. }, Some(want)) =
            (&decision.outcome, step.arr("denied_by"))
        {
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
        if let (Outcome::Escalate { trigger, limit, .. }, Some(e)) =
            (&decision.outcome, step.get("escalation"))
        {
            if let Some(want) = e.str("trigger") {
                if want != *trigger {
                    failures.push(format!(
                        "request {n}: escalated on {trigger:?}, expected {want:?}"
                    ));
                }
            }
            if let Some(want) = e.str("limit") {
                if want != limit {
                    failures.push(format!("request {n}: escalated on {limit}, expected {want}"));
                }
            }
        }

        if let Err(e) = pays_policy::check_invariant(&compiled, &ledger) {
            failures.push(format!("request {n}: invariant violated: {e}"));
        }
    }

    VectorResult { name, failures }
}

#[test]
fn eval_vectors() {
    let Some(root) = corpus() else {
        eprintln!("corpus not found; skipping");
        return;
    };
    let dir = root.join("eval");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no eval vectors found in {}", dir.display());

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
