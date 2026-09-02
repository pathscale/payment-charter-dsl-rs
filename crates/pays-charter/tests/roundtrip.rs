//! `roundtrip/`: text → AST → text, byte-identical (§1.2).
//!
//! The canonical form of a canonical document is itself. That is the whole property, and it is
//! what makes the comparison a byte comparison rather than a semantic one — two emitters can
//! agree on every meaning and still disagree on every character a human reads.
//!
//! Also emits every `parse/accept/` fixture and re-parses the result, which catches an emitter
//! that produces something this parser will not take.

use std::path::{Path, PathBuf};

fn corpus() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CHARTER_CORPUS") {
        let p = PathBuf::from(p);
        return p.is_dir().then_some(p);
    }
    let s = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../payment-charter-dsl/conformance");
    s.is_dir().then(|| s.canonicalize().unwrap())
}

fn charters(dir: &Path) -> Vec<PathBuf> {
    if !dir.is_dir() {
        return Vec::new();
    }
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "charter"))
        .collect();
    v.sort();
    v
}

#[test]
fn emitting_an_accept_fixture_produces_something_this_parser_accepts() {
    let Some(root) = corpus() else { return };
    let mut failures = Vec::new();
    for f in charters(&root.join("parse/accept")) {
        let src = std::fs::read_to_string(&f).unwrap();
        let Ok(ast) = pays_charter::parse(&src) else { continue };
        let text = pays_charter::emit(&ast);
        if let Err(e) = pays_charter::parse(&text) {
            failures.push(format!(
                "{}: emitted text did not re-parse: {}\n--- emitted ---\n{text}",
                f.file_name().unwrap().to_string_lossy(),
                e[0].render(&text)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn emission_is_idempotent() {
    // Without this an emitter could produce accepted-but-unstable output, and a byte
    // comparison against a stored fixture would be the only thing that ever noticed.
    let Some(root) = corpus() else { return };
    let mut failures = Vec::new();
    for f in charters(&root.join("parse/accept")) {
        let src = std::fs::read_to_string(&f).unwrap();
        let Ok(ast) = pays_charter::parse(&src) else { continue };
        let once = pays_charter::emit(&ast);
        let Ok(again) = pays_charter::parse(&once) else { continue };
        let twice = pays_charter::emit(&again);
        if once != twice {
            failures.push(format!(
                "{}: not idempotent\n--- once ---\n{once}\n--- twice ---\n{twice}",
                f.file_name().unwrap().to_string_lossy()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn roundtrip_fixtures_are_already_canonical() {
    // A fixture in roundtrip/ is stored in canonical form, so emitting it must reproduce it
    // byte for byte. This is the fixture directory the TypeScript emitter is also held to.
    let Some(root) = corpus() else { return };
    let files = charters(&root.join("roundtrip"));
    assert!(!files.is_empty(), "roundtrip/ is empty");
    let mut failures = Vec::new();
    for f in files {
        let src = std::fs::read_to_string(&f).unwrap();
        let ast = match pays_charter::parse(&src) {
            Ok(a) => a,
            Err(e) => {
                failures.push(format!("{}: {}", f.display(), e[0].render(&src)));
                continue;
            }
        };
        let text = pays_charter::emit(&ast);
        if text != src {
            failures.push(format!(
                "{}: not canonical\n--- stored ---\n{src}\n--- emitted ---\n{text}",
                f.file_name().unwrap().to_string_lossy()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
