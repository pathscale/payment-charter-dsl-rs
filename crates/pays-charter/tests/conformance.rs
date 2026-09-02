//! Runs the shared conformance corpus.
//!
//! The corpus lives in the spec repo and is what "conforming" means — these tests are the
//! only ones that can fail for a reason the TypeScript implementation would also hit.
//! Local unit tests are welcome and are not a substitute.
//!
//! Point CHARTER_CORPUS at the checkout; the sibling default covers the usual layout.

use std::path::{Path, PathBuf};

fn corpus() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CHARTER_CORPUS") {
        let p = PathBuf::from(p);
        return p.is_dir().then_some(p);
    }
    let sibling = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../payment-charter-dsl/conformance");
    sibling.is_dir().then(|| sibling.canonicalize().unwrap())
}

fn charters(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "charter"))
        .collect();
    v.sort();
    v
}

/// §11: a reject case carries its expected code in the **leading comment block**, not
/// necessarily on the first line, because a fixture derived from an upstream suite carries a
/// provenance header first.
fn expected_code(src: &str) -> Option<String> {
    for line in src.lines() {
        let t = line.trim_start();
        if !t.starts_with('#') {
            break;
        }
        if let Some(rest) = t.trim_start_matches('#').trim().strip_prefix("expect:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

#[test]
fn every_reject_fixture_declares_its_code() {
    let Some(root) = corpus() else {
        eprintln!("corpus not found; skipping");
        return;
    };
    let mut bad = Vec::new();
    for f in charters(&root.join("parse/reject")) {
        let src = std::fs::read_to_string(&f).unwrap();
        if expected_code(&src).is_none() {
            bad.push(f);
        }
    }
    assert!(bad.is_empty(), "reject fixtures with no `# expect:` in the leading block: {bad:#?}");
}

/// Parse-level accept: the fixture must at least tokenise and parse. Static rules are a
/// separate pass, so a fixture that parses and later fails a rule is reported by
/// `reject_fixtures` rather than here.
#[test]
fn accept_fixtures_parse() {
    let Some(root) = corpus() else {
        eprintln!("corpus not found; skipping");
        return;
    };
    let mut failures = Vec::new();
    for dir in ["parse/accept", "asset-ref"] {
        let d = root.join(dir);
        if !d.is_dir() {
            continue;
        }
        for f in charters(&d) {
            let src = std::fs::read_to_string(&f).unwrap();
            if let Err(errs) = pays_charter::check(&src) {
                let rendered: Vec<_> = errs.iter().map(|e| e.render(&src)).collect();
                failures.push(format!("{}\n    {}", f.display(), rendered.join("\n    ")));
            }
        }
    }
    assert!(failures.is_empty(), "accept fixtures that failed to parse:\n{}", failures.join("\n"));
}

/// Reject fixtures whose expected code is a *parse-or-lex* one must produce exactly that
/// code. A fixture expecting a static-rule code is skipped here with a count, because the
/// rules pass is not wired yet — silence would read as coverage.
#[test]
fn reject_fixtures_report_the_right_code() {
    let Some(root) = corpus() else {
        eprintln!("corpus not found; skipping");
        return;
    };
    // Codes this crate can currently decide. Everything else is a static rule.
    const DECIDED: &[&str] = &[
        "E101", "E102", "E103", "E201", "E210", "E211", "E212", "E213", "E214", "E215",
        "E216", "E217", "E218", "E220", "E222", "E306", "E307", "E308", "E309", "E310",
        "E311", "E312", "E314", "E316", "E317", "E403", "E410", "E411", "E413",
    ];

    let mut wrong = Vec::new();
    let mut deferred = Vec::new();
    for f in charters(&root.join("parse/reject")) {
        let src = std::fs::read_to_string(&f).unwrap();
        let want = expected_code(&src).expect("checked by the fixture test");
        let got = pays_charter::check(&src).err().map(|es| {
            es.iter().filter(|d| d.is_error()).map(|d| d.code.to_string()).collect::<Vec<_>>()
        });

        if !DECIDED.contains(&want.as_str()) {
            deferred.push(format!("{} wants {want}", f.file_name().unwrap().to_string_lossy()));
            continue;
        }
        match got {
            Some(codes) if codes.contains(&want) => {}
            Some(codes) => wrong.push(format!(
                "{}: wanted {want}, got {codes:?}",
                f.file_name().unwrap().to_string_lossy()
            )),
            None => wrong.push(format!(
                "{}: wanted {want}, but it compiled",
                f.file_name().unwrap().to_string_lossy()
            )),
        }
    }
    // Report what is not yet covered rather than passing quietly over it.
    eprintln!("{} reject fixtures await the static-rules pass:", deferred.len());
    for d in &deferred {
        eprintln!("  {d}");
    }
    assert!(wrong.is_empty(), "wrong error code:\n  {}", wrong.join("\n  "));
}

/// `type-table/`: §6's field × operator cross product, generated rather than hand-written.
///
/// Most of the 84 combinations are invalid and must produce E301. A file with an `# expect:`
/// line is one of those; a file without one must compile. Generating them is the point — a
/// hand-written sample of a cross product tests the cells somebody thought of.
#[test]
fn type_table_cross_product() {
    let Some(root) = corpus() else { return };
    let dir = root.join("type-table");
    if !dir.is_dir() {
        return;
    }
    let files = charters(&dir);
    assert!(files.len() >= 80, "expected the full cross product, found {}", files.len());

    let mut failures = Vec::new();
    let (mut accepted, mut rejected) = (0, 0);
    for f in files {
        let src = std::fs::read_to_string(&f).unwrap();
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        let want = expected_code(&src);
        let got = pays_charter::check(&src);
        match (&want, &got) {
            (None, Ok(_)) => accepted += 1,
            (None, Err(e)) => failures.push(format!(
                "{name}: should compile, got {}",
                e.iter().map(|d| d.code).collect::<Vec<_>>().join(", ")
            )),
            (Some(code), Err(e)) => {
                if e.iter().any(|d| d.code == code) {
                    rejected += 1;
                } else {
                    failures.push(format!(
                        "{name}: wanted {code}, got {}",
                        e.iter().map(|d| d.code).collect::<Vec<_>>().join(", ")
                    ));
                }
            }
            (Some(code), Ok(_)) => failures.push(format!("{name}: wanted {code}, but it compiled")),
        }
    }
    eprintln!("type table: {accepted} accepted, {rejected} rejected");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `resolver/`: S7–S13, against the `common` tier in the spec repo.
///
/// These cannot live in `parse/reject/` because they need data the text does not carry. A
/// document here is well-formed and refused for what the resolver says about it, which is a
/// different kind of refusal and worth keeping visibly separate.
#[test]
fn resolver_fixtures() {
    let Some(root) = corpus() else { return };
    let dir = root.join("resolver");
    if !dir.is_dir() {
        return;
    }
    let tier = std::fs::read_to_string(root.join("../resolver/common-41.json"))
        .expect("the common tier ships with the corpus");
    let resolver = pays_charter::Resolver::from_json(&tier).expect("the common tier parses");

    let mut failures = Vec::new();
    for f in charters(&dir) {
        let src = std::fs::read_to_string(&f).unwrap();
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        let want = expected_code(&src);

        let ast = match pays_charter::parse(&src) {
            Ok(a) => a,
            Err(e) => {
                failures.push(format!("{name}: did not parse: {}", e[0].render(&src)));
                continue;
            }
        };
        let diags = pays_charter::resolver::check(&ast, &resolver);
        let codes: Vec<&str> = diags.iter().filter(|d| d.is_error()).map(|d| d.code).collect();

        match &want {
            Some(code) if codes.contains(&code.as_str()) => {}
            Some(code) => {
                failures.push(format!("{name}: wanted {code}, got {codes:?}"));
            }
            None if codes.is_empty() => {}
            None => failures.push(format!("{name}: should resolve cleanly, got {codes:?}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `ported/`: cases taken from upstream suites, each carrying its provenance header.
///
/// Attribution is not optional and the headers are not decoration: `AGENTS.md` in the corpus
/// repo carves these out of the house rule against copyright banners so an agent tidying the
/// tree does not strip them.
#[test]
fn ported_fixtures() {
    let Some(root) = corpus() else { return };
    let dir = root.join("ported/catala");
    if !dir.is_dir() {
        return;
    }
    let files = charters(&dir);
    assert!(!files.is_empty(), "ported/catala is empty");

    let mut failures = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap();
        let name = f.file_name().unwrap().to_string_lossy().to_string();

        // Every ported fixture must say where it came from.
        assert!(
            src.contains("Derived from CatalaLang/catala"),
            "{name} has no provenance header"
        );
        assert!(src.contains("Apache-2.0"), "{name} does not name the upstream licence");

        let want = expected_code(&src);
        match (&want, pays_charter::check(&src)) {
            (None, Ok(_)) => {}
            (None, Err(e)) => failures.push(format!(
                "{name}: should compile, got {}",
                e.iter().map(|d| d.code).collect::<Vec<_>>().join(", ")
            )),
            (Some(code), Err(e)) if e.iter().any(|d| d.code == code) => {}
            (Some(code), Err(e)) => failures.push(format!(
                "{name}: wanted {code}, got {}",
                e.iter().map(|d| d.code).collect::<Vec<_>>().join(", ")
            )),
            (Some(code), Ok(_)) => failures.push(format!("{name}: wanted {code}, but it compiled")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
