# payment-charter-dsl-rs

The reference implementation of the [Payment Charter DSL](https://github.com/pathscale/payment-charter-dsl)
in Rust: lexer, parser, AST, emitter, static rules, and the compiled form.

The specification lives in the [spec repo](https://github.com/pathscale/payment-charter-dsl) and
is normative. So does the conformance corpus. This repo is judged by that corpus, not by its own
tests.

## Build order

This is the first implementation, so it defines the shape the TypeScript one follows. Build it
in this order — each step is what makes the next one testable:

1. **The asset reference sub-parser** (its own crate). `mint://` and `unit://` are lexed as a
   single token and decomposed here. Everything else depends on it, and a large, cheap slice of
   the corpus lives against it.
2. **Lexer, parser, AST.**
3. **Static rules** S1–S16 and hierarchy H1–H6, with the error catalogue.
4. **Emitter**, producing the canonical text form of §1.1.
5. **Compiled form** and the evaluator.

[`docs/handover-charter-parser.md`](docs/handover-charter-parser.md) is the build instruction:
crate split, what to write first, and what survives from the placeholder engine.

## Crate split

| Crate | Role |
|---|---|
| `pays-charter` | Compiles: lexer, parser, static rules, resolver checks, diagnostics. **May** take dependencies — it runs in the backend and the CLI. |
| `pays-policy` | Evaluates the compiled form. **Dependency-free.** This is the only half the enclave links. |
| asset-reference crate | The `mint://` / `unit://` parser, shared by both and by the resolver service. |

**The enclave never parses text.** That is the reason for the split, and it is not negotiable:
`pays-policy` takes a compiled charter and nothing else.

## Dependencies — decided, do not relitigate

- `logos` for the lexer. Zero runtime dependencies, and it handles the multi-word tokens
  (`is not`, `not in`, `is at least`, `up to`, `when exhausted`) as single tokens, which is what
  removes the ambiguity between the `not` of negation and the `not` of an operator.
- **Hand-written recursive descent** for the parser. No parser combinator library.
- `annotate-snippets` for diagnostics, pulling `anstyle` and `unicode-width`. It is what
  `rustc_errors` itself depends on.
- **LALRPOP as a CI-only unambiguity proof**, differential-tested against the shipped parser. It
  is not in the shipped dependency graph.
- `serde` + JSON for the wire form. Not TOON: the data is a nested tree, which is what TOON is
  worst at, and JSON has a canonicalisation standard (JCS, RFC 8785) that matters the moment a
  charter is signed.
- **Regorus is out.** Zero lines, not a dependency, not an inspiration.

## The asset reference is a parser, not `split('/')`

Four reasons, all of which bite:

1. **Sub-spans.** E401 says *which segment* disagrees with the resolver, so the diagnostic
   underlines the issuer inside the reference rather than the whole token. That needs byte
   offsets tracked within the token.
2. **Two input grammars, one canonical output.** The native form and CAIP-19 (§2.10) denote the
   same object; the second normalises into the first with `symbol` and `issuer` filled from the
   resolver. Emission is always the native form.
3. **Per-namespace validation (S9).** `solana` requires 32–44 base58 excluding `0 O I l`;
   `eip155` requires `0x` and 40 hex. A dispatch table keyed on the CAIP-2 namespace, where an
   unknown namespace is E403 rather than silently accepted.
4. **Everything else needs it** — the resolver, the wire form, `resolved_assets` in the compiled
   form, and the TypeScript emitter. One implementation, not three that drift.

## Binary size

Unmeasured, estimated from component sizes; pin these with a skeleton build before trusting them.

| Target | Estimate |
|---|---|
| `pays-policy` (enclave half) | 80–200 KB |
| `pays-charter` added to a host binary | 500 KB – 1 MB, dominated by `serde_json` and `unicode-width` tables |
| Standalone CLI, `opt-level="z"` + LTO + strip | 1.5–3 MB |

## Licence

Dual [Apache-2.0](LICENSE-APACHE) / [MIT](LICENSE-MIT), at your option.
