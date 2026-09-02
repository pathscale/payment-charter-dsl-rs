//! Charter authenticity (§12).
//!
//! The host is untrusted by design. Faithful enforcement of a charter the host chose is not
//! enforcement, so **there is no unsigned path**: an engine rejects any charter that does not
//! arrive with a valid controller signature.
//!
//! What is signed is not the charter but a commitment carrying two digests. `compiled_digest`
//! covers what this engine evaluates; `text_digest` covers the canonical text a human read.
//! Signing only the compiled form would have the controller attesting to bytes they never saw,
//! which is the display-one-sign-another gap the whole system exists to close for payments.
//! To this engine `text_digest` is opaque 32 bytes — it never parses text.
//!
//! **Signature verification is behind [`Verifier`] and is not implemented here.** Hand-rolled
//! Ed25519 in the one component whose whole job is refusing forgeries would be indefensible;
//! `ed25519-dalek` plugs in at the boundary. SHA-256 and JCS *are* implemented, because they
//! are fully specified, cheap to test against published vectors, and dragging a dependency
//! into the enclave for them costs more than it saves.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// The signed payload (§12.3). Serialised with JCS (RFC 8785) and signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub charter: String,
    pub version: u64,
    /// SHA-256 of the canonical text form (§1.2) — the only field binding the signature to
    /// something a human read. Opaque here.
    pub text_digest: [u8; 32],
    /// SHA-256 of the compiled form (§9) — what this engine evaluates.
    pub compiled_digest: [u8; 32],
    pub key_id: String,
    /// Unix epoch seconds, UTC. Not a formatted timestamp: a date format has more than one
    /// spelling of the same instant, which would need a second canonicalisation nested inside
    /// JCS, and would put a date parser in the enclave.
    pub not_before: i64,
    pub not_after: i64,
}

/// Errors from §12.4, in the order they are checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// E501 — the signature does not verify over the JCS-canonicalised commitment.
    SignatureInvalid,
    /// E502 — `key_id` names no key in the trust root.
    UnknownKey,
    /// E503 — the compiled form is not the one the commitment names.
    CompiledDigestMismatch,
    /// E504 — anti-rollback. A replayed lower version is a permissive charter returning.
    VersionNotMonotonic,
    /// E505 — outside `[not_before, not_after)`.
    OutsideValidity,
    /// E506 — the commitment names a different charter. Without this, a signed commitment for
    /// a permissive charter replays against a restrictive one.
    CharterNameMismatch,
}

impl AuthError {
    pub fn code(self) -> &'static str {
        match self {
            AuthError::SignatureInvalid => "E501",
            AuthError::UnknownKey => "E502",
            AuthError::CompiledDigestMismatch => "E503",
            AuthError::VersionNotMonotonic => "E504",
            AuthError::OutsideValidity => "E505",
            AuthError::CharterNameMismatch => "E506",
        }
    }
}

/// Signature verification, supplied by the host of this crate.
///
/// The enclave's build wires a real Ed25519 verifier; tests wire a double. The trait exists so
/// that no version of this crate can be built with signature checking quietly absent — an
/// implementation must be provided for [`verify`] to be callable at all.
pub trait Verifier {
    /// Is `key_id` in the trust root? §12.5: the key set is established at provisioning and is
    /// part of what the attestation covers.
    fn knows(&self, key_id: &str) -> bool;

    /// Verify `signature` over `message` under `key_id`.
    fn verify(&self, key_id: &str, message: &[u8], signature: &[u8]) -> bool;
}

/// The highest version yet installed for a charter name — the anti-rollback counter.
///
/// It costs nothing because the header already carries `charter <name> version <uint>` (§3).
/// That field was there for humans and is exactly the monotonic counter the engine needs.
pub trait VersionStore {
    fn highest(&self, charter: &str) -> Option<u64>;
}

/// §12.4, failing closed at the first failure and in this order.
pub fn verify(
    commitment: &Commitment,
    signature: &[u8],
    compiled_bytes: &[u8],
    installing: &str,
    now: i64,
    verifier: &impl Verifier,
    versions: &impl VersionStore,
) -> Result<(), AuthError> {
    if !verifier.knows(&commitment.key_id) {
        return Err(AuthError::UnknownKey);
    }
    let message = jcs(commitment);
    if !verifier.verify(&commitment.key_id, message.as_bytes(), signature) {
        return Err(AuthError::SignatureInvalid);
    }
    if now < commitment.not_before || now >= commitment.not_after {
        return Err(AuthError::OutsideValidity);
    }
    if commitment.charter != installing {
        return Err(AuthError::CharterNameMismatch);
    }
    if let Some(highest) = versions.highest(installing) {
        if commitment.version <= highest {
            return Err(AuthError::VersionNotMonotonic);
        }
    }
    if sha256(compiled_bytes) != commitment.compiled_digest {
        return Err(AuthError::CompiledDigestMismatch);
    }
    Ok(())
}

/// JCS (RFC 8785) for this commitment's fixed shape.
///
/// A general JCS implementation is not needed and would be more to get wrong: the payload has
/// six known keys and no nesting, so canonicalisation is sorting them and emitting without
/// whitespace. Digests are lowercase hex strings and the two timestamps are integers, so no
/// number here can reach the 2^53 cliff that made money a string (§1.1).
pub fn jcs(c: &Commitment) -> String {
    // Keys sorted by UTF-16 code unit, which for these ASCII names is byte order:
    // charter, compiled_digest, key_id, not_after, not_before, text_digest, version.
    format!(
        concat!(
            "{{\"charter\":\"{}\",",
            "\"compiled_digest\":\"{}\",",
            "\"key_id\":\"{}\",",
            "\"not_after\":{},",
            "\"not_before\":{},",
            "\"text_digest\":\"{}\",",
            "\"version\":{}}}"
        ),
        escape(&c.charter),
        hex(&c.compiled_digest),
        escape(&c.key_id),
        c.not_after,
        c.not_before,
        hex(&c.text_digest),
        c.version,
    )
}

/// §2.4 admits no escapes in a charter name and §12's `key_id` is opaque, so this handles the
/// two characters JSON requires and refuses to invent behaviour for the rest.
fn escape(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out
}

pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 0xf) as usize] as char);
    }
    s
}

// ------------------------------------------------------------------ SHA-256

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256, FIPS 180-4. Implemented rather than depended on: it is fully specified, testable
/// against published vectors, and the enclave half of this system carries no dependencies.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut msg: Vec<u8> = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    // Not in the no_std prelude, and the lib itself does not need it — which is why a
    // build-only check missed this and only `cargo test` caught it.
    use alloc::string::ToString;
    

    #[test]
    fn sha256_matches_the_published_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // Crosses the padding boundary in both directions.
        assert_eq!(
            hex(&sha256(&[b'a'; 55])),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );
        assert_eq!(
            hex(&sha256(&[b'a'; 56])),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
    }

    struct Trusted(&'static str);
    impl Verifier for Trusted {
        fn knows(&self, key_id: &str) -> bool {
            key_id == self.0
        }
        // A double: a "signature" is the message's own digest. Enough to exercise §12.4's
        // ordering and tampering; the real thing is Ed25519 at this boundary.
        fn verify(&self, _key_id: &str, message: &[u8], signature: &[u8]) -> bool {
            signature == sha256(message)
        }
    }

    struct Versions(BTreeMap<String, u64>);
    impl VersionStore for Versions {
        fn highest(&self, charter: &str) -> Option<u64> {
            self.0.get(charter).copied()
        }
    }

    fn fixture() -> (Commitment, Vec<u8>, Vec<u8>) {
        let compiled = b"compiled bytes".to_vec();
        let c = Commitment {
            charter: "acme-treasury".to_string(),
            version: 7,
            text_digest: sha256(b"charter acme-treasury version 7\n"),
            compiled_digest: sha256(&compiled),
            key_id: "controller-1".to_string(),
            not_before: 1_788_271_200,
            not_after: 1_819_807_200,
        };
        let sig = sha256(jcs(&c).as_bytes()).to_vec();
        (c, compiled, sig)
    }

    fn versions() -> Versions {
        Versions(BTreeMap::new())
    }

    #[test]
    fn a_well_formed_commitment_verifies() {
        let (c, compiled, sig) = fixture();
        assert_eq!(
            verify(&c, &sig, &compiled, "acme-treasury", 1_788_300_000, &Trusted("controller-1"), &versions()),
            Ok(())
        );
    }

    #[test]
    fn an_unknown_key_is_refused_before_anything_else() {
        let (c, compiled, sig) = fixture();
        assert_eq!(
            verify(&c, &sig, &compiled, "acme-treasury", 1_788_300_000, &Trusted("someone-else"), &versions()),
            Err(AuthError::UnknownKey)
        );
    }

    #[test]
    fn tampering_with_any_field_breaks_the_signature() {
        // Every field is inside the signed bytes, which is the point of signing a commitment
        // rather than signing the compiled form alone.
        let (base, compiled, sig) = fixture();
        for mutate in [
            (|c: &mut Commitment| c.version = 8) as fn(&mut Commitment),
            |c| c.charter = "other".to_string(),
            |c| c.not_after += 1,
            |c| c.text_digest = [0; 32],
            |c| c.compiled_digest = [0; 32],
        ] {
            let mut c = base.clone();
            mutate(&mut c);
            assert_eq!(
                verify(&c, &sig, &compiled, &c.charter.clone(), 1_788_300_000, &Trusted("controller-1"), &versions()),
                Err(AuthError::SignatureInvalid),
            );
        }
    }

    #[test]
    fn a_compiled_form_the_commitment_does_not_name_is_refused() {
        // The attack this closes: a valid signature over one charter, presented alongside a
        // different compiled form.
        let (c, _, sig) = fixture();
        assert_eq!(
            verify(&c, &sig, b"different bytes", "acme-treasury", 1_788_300_000, &Trusted("controller-1"), &versions()),
            Err(AuthError::CompiledDigestMismatch)
        );
    }

    #[test]
    fn a_replayed_version_is_refused() {
        let (c, compiled, sig) = fixture();
        let mut v = versions();
        v.0.insert("acme-treasury".to_string(), 7);
        assert_eq!(
            verify(&c, &sig, &compiled, "acme-treasury", 1_788_300_000, &Trusted("controller-1"), &v),
            Err(AuthError::VersionNotMonotonic),
            "last quarter's more generous charter must not come back"
        );
        v.0.insert("acme-treasury".to_string(), 6);
        assert_eq!(
            verify(&c, &sig, &compiled, "acme-treasury", 1_788_300_000, &Trusted("controller-1"), &v),
            Ok(())
        );
    }

    #[test]
    fn a_commitment_for_another_charter_does_not_replay() {
        let (c, compiled, sig) = fixture();
        assert_eq!(
            verify(&c, &sig, &compiled, "restrictive-charter", 1_788_300_000, &Trusted("controller-1"), &versions()),
            Err(AuthError::CharterNameMismatch)
        );
    }

    #[test]
    fn validity_is_half_open() {
        let (c, compiled, sig) = fixture();
        let at = |t| verify(&c, &sig, &compiled, "acme-treasury", t, &Trusted("controller-1"), &versions());
        assert_eq!(at(c.not_before - 1), Err(AuthError::OutsideValidity));
        assert_eq!(at(c.not_before), Ok(()));
        assert_eq!(at(c.not_after - 1), Ok(()));
        assert_eq!(
            at(c.not_after),
            Err(AuthError::OutsideValidity),
            "not_after is exclusive, so staleness becomes a liveness failure with a deadline"
        );
    }

    #[test]
    fn jcs_sorts_keys_and_emits_no_whitespace() {
        let (c, _, _) = fixture();
        let s = jcs(&c);
        assert!(!s.contains(' '), "JCS emits no whitespace: {s}");
        let order = ["charter", "compiled_digest", "key_id", "not_after", "not_before", "text_digest", "version"];
        let mut last = 0;
        for k in order {
            let at = s.find(k).unwrap_or_else(|| panic!("{k} missing from {s}"));
            assert!(at > last, "{k} out of order in {s}");
            last = at;
        }
        // Timestamps are integers, so nothing here can reach the 2^53 cliff that made money a
        // string (§1.1).
        assert!(s.contains("\"not_before\":1788271200"));
    }
}
