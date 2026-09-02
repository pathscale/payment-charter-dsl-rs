//! Runs `conformance/authenticity/*.json` (§12).
//!
//! The fixtures use a stand-in signature scheme — the signature is the message's own digest —
//! because what is under test is §12.4's *ordering and coverage*, not Ed25519. Every fixture
//! is the valid one with exactly one thing wrong, so a check that silently stopped running
//! would show up as a fixture passing for the wrong reason.

use pays_policy::authenticity::{jcs, sha256, verify, AuthError, Commitment, Verifier, VersionStore};
use std::path::{Path, PathBuf};

#[path = "json.rs"]
mod json;
use json::Json;

fn corpus() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CHARTER_CORPUS") {
        let p = PathBuf::from(p);
        return p.is_dir().then_some(p);
    }
    let s = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../payment-charter-dsl/conformance");
    s.is_dir().then(|| s.canonicalize().unwrap())
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn digest32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

struct Keys(Vec<String>);
impl Verifier for Keys {
    fn knows(&self, key_id: &str) -> bool {
        self.0.iter().any(|k| k == key_id)
    }
    fn verify(&self, _key_id: &str, message: &[u8], signature: &[u8]) -> bool {
        signature == sha256(message)
    }
}

struct Highest(Option<u64>);
impl VersionStore for Highest {
    fn highest(&self, _charter: &str) -> Option<u64> {
        self.0
    }
}

#[test]
fn authenticity_fixtures() {
    let Some(root) = corpus() else { return };
    let dir = root.join("authenticity");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "authenticity/ is empty");

    let mut failures = Vec::new();
    for f in &files {
        let raw = std::fs::read_to_string(f).unwrap();
        let v = json::parse(&raw);
        let c = v.get("commitment").expect("commitment");

        let commitment = Commitment {
            charter: c.str("charter").unwrap().to_string(),
            version: c.num("version").unwrap() as u64,
            text_digest: digest32(c.str("text_digest").unwrap()),
            compiled_digest: digest32(c.str("compiled_digest").unwrap()),
            key_id: c.str("key_id").unwrap().to_string(),
            not_before: c.num("not_before").unwrap() as i64,
            not_after: c.num("not_after").unwrap() as i64,
        };

        let keys = Keys(
            v.arr("trusted_keys")
                .unwrap_or(&[])
                .iter()
                .filter_map(|j| match j {
                    Json::Str(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
        );
        let highest = Highest(v.num("highest_version").map(|n| n as u64));

        let got = verify(
            &commitment,
            &unhex(v.str("signature").unwrap()),
            &unhex(v.str("compiled").unwrap()),
            v.str("installing").unwrap(),
            v.num("now").unwrap() as i64,
            &keys,
            &highest,
        );
        let got_code = match got {
            Ok(()) => "ok".to_string(),
            Err(e) => e.code().to_string(),
        };
        let want = v.str("expect").unwrap();
        if got_code != want {
            failures.push(format!(
                "{}: expected {want}, got {got_code}",
                f.file_name().unwrap().to_string_lossy()
            ));
        } else {
            eprintln!("  ok   {} -> {want}", f.file_name().unwrap().to_string_lossy());
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_fixture_is_the_valid_one_with_one_thing_wrong() {
    // If a fixture drifted so that two things were wrong at once, it would still pass while
    // testing something other than the check it names.
    let Some(root) = corpus() else { return };
    let raw = std::fs::read_to_string(root.join("authenticity/valid.json")).unwrap();
    let v = json::parse(&raw);
    let c = v.get("commitment").unwrap();
    let commitment = Commitment {
        charter: c.str("charter").unwrap().to_string(),
        version: c.num("version").unwrap() as u64,
        text_digest: digest32(c.str("text_digest").unwrap()),
        compiled_digest: digest32(c.str("compiled_digest").unwrap()),
        key_id: c.str("key_id").unwrap().to_string(),
        not_before: c.num("not_before").unwrap() as i64,
        not_after: c.num("not_after").unwrap() as i64,
    };
    assert_eq!(
        unhex(v.str("signature").unwrap()),
        sha256(jcs(&commitment).as_bytes()),
        "valid.json's signature must actually cover its own commitment"
    );
    assert!(matches!(
        verify(
            &commitment,
            &unhex(v.str("signature").unwrap()),
            &unhex(v.str("compiled").unwrap()),
            v.str("installing").unwrap(),
            v.num("now").unwrap() as i64,
            &Keys(vec!["controller-1".into()]),
            &Highest(None),
        ),
        Ok(())
    ));
    let _ = AuthError::SignatureInvalid;
}
