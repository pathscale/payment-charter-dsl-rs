//! Writes `conformance/authenticity/*.json`. Run once when the fixture set changes; the
//! output is committed, because a fixture generated at test time proves only that the
//! generator agrees with itself.

use pays_policy::authenticity::{hex, jcs, sha256, Commitment};

fn main() {
    let out = std::env::args().nth(1).expect("usage: gen-auth-fixtures <dir>");
    let compiled = b"compiled bytes for acme-treasury v7".to_vec();
    let base = Commitment {
        charter: "acme-treasury".into(),
        version: 7,
        text_digest: sha256(b"charter acme-treasury version 7\n"),
        compiled_digest: sha256(&compiled),
        key_id: "controller-1".into(),
        not_before: 1_788_271_200,
        not_after: 1_819_807_200,
    };
    let good_sig = sha256(jcs(&base).as_bytes());

    let render = |name: &str, desc: &str, c: &Commitment, sig: &[u8], compiled: &[u8],
                  installing: &str, now: i64, keys: &str, highest: &str, expect: &str| {
        let body = format!(
            concat!(
            "{{\n",
            "  \"description\": \"{desc}\",\n",
            "  \"commitment\": {{\n",
            "    \"charter\": \"{charter}\",\n",
            "    \"version\": {version},\n",
            "    \"text_digest\": \"{td}\",\n",
            "    \"compiled_digest\": \"{cd}\",\n",
            "    \"key_id\": \"{key}\",\n",
            "    \"not_before\": {nb},\n",
            "    \"not_after\": {na}\n",
            "  }},\n",
            "  \"signature\": \"{sig}\",\n",
            "  \"compiled\": \"{compiled}\",\n",
            "  \"installing\": \"{installing}\",\n",
            "  \"now\": {now},\n",
            "  \"trusted_keys\": {keys},\n",
            "  \"highest_version\": {highest},\n",
            "  \"expect\": \"{expect}\"\n",
            "}}\n"),
            desc = desc, charter = c.charter, version = c.version,
            td = hex(&c.text_digest), cd = hex(&c.compiled_digest), key = c.key_id,
            nb = c.not_before, na = c.not_after,
            sig = hex(sig), compiled = hex(compiled),
            installing = installing, now = now, keys = keys, highest = highest, expect = expect,
        );
        std::fs::write(format!("{out}/{name}.json"), body).unwrap();
    };

    let now = 1_788_300_000;
    let keys = "[\"controller-1\"]";

    render("valid.json".trim_end_matches(".json"),
        "A well-formed commitment. Every later fixture is this one with a single thing wrong.",
        &base, &good_sig, &compiled, "acme-treasury", now, keys, "null", "ok");

    render("unknown-key",
        "E502 - key_id names no key in the trust root. Checked before the signature, because a signature under an untrusted key is not worth computing.",
        &base, &good_sig, &compiled, "acme-treasury", now, "[\"someone-else\"]", "null", "E502");

    let mut tampered = base.clone();
    tampered.version = 8;
    render("tampered-version",
        "E501 - the version is inside the signed bytes, so raising it breaks the signature. This is why a commitment is signed rather than the compiled form alone.",
        &tampered, &good_sig, &compiled, "acme-treasury", now, keys, "null", "E501");

    render("compiled-digest-mismatch",
        "E503 - a valid signature over one charter, presented with a different compiled form. The engine evaluates the compiled bytes, so this is the substitution the second digest exists to catch.",
        &base, &good_sig, b"a different compiled form", "acme-treasury", now, keys, "null", "E503");

    render("replayed-version",
        "E504 - anti-rollback. Version 7 arriving when 7 is already installed is last quarter's more generous charter coming back.",
        &base, &good_sig, &compiled, "acme-treasury", now, keys, "7", "E504");

    render("wrong-charter-name",
        "E506 - a commitment for one charter replayed against another. Without this check, a signed permissive charter installs over a restrictive one.",
        &base, &good_sig, &compiled, "restrictive", now, keys, "null", "E506");

    render("expired",
        "E505 - not_after is exclusive. A charter that outlives its window stops, so staleness is a liveness failure with a deadline rather than a silent indefinite one.",
        &base, &good_sig, &compiled, "acme-treasury", base.not_after, keys, "null", "E505");

    render("not-yet-valid",
        "E505 - the other edge. not_before is inclusive; one second earlier is not.",
        &base, &good_sig, &compiled, "acme-treasury", base.not_before - 1, keys, "null", "E505");

    eprintln!("wrote 8 fixtures to {out}");
}
