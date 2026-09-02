# Working agreement — payment-charter-dsl-rs

The operating contract for **any** coding agent working in this repository. This file is the
single source of truth for the rules: Codex, Cursor and Gemini CLI read `AGENTS.md` natively,
and Claude Code loads it through the `@AGENTS.md` import in [`CLAUDE.md`](CLAUDE.md). **Never
fork these rules into a per-vendor file.**

**Rust reference implementation** of the [Payment Charter DSL](https://github.com/pathscale/payment-charter-dsl).

## Invariants (don't break these)

- **The spec is normative and lives in another repo.** Build against
  [`spec.md`](https://github.com/pathscale/payment-charter-dsl/blob/master/spec.md). If the
  implementation and the spec disagree, the spec is right and the fix goes here. If the spec is
  actually wrong, fix it *there* first, with fixtures, and then follow.

- **`pays-policy` is dependency-free and never parses text.** It links into the enclave. It
  takes a compiled charter and nothing else. Adding a dependency to it, or a parser, defeats the
  reason the crate split exists.

- **`pays-charter` may take dependencies.** It runs in the backend and the CLI.

- **Conformance is the shared corpus, not local tests.** The suite in the spec repo is what
  "conforming" means. Local unit tests are welcome and are not a substitute.

- **No Python.** Not a script, not `python3 -c`, not a heredoc. Do not assume `jq` is present:
  it does not ship with macOS.

- **Docs describe what is true now.** Behaviour change and README change land together.

## Decided dependencies — do not relitigate without new information

`logos` (lexer), hand-written recursive descent (parser, **no combinator library**),
`annotate-snippets` (diagnostics), LALRPOP **CI-only** as an unambiguity proof differential-
tested against the shipped parser, `serde` + JSON for the wire form.

**Regorus is out** — zero lines, not a dependency, not an inspiration. **TOON is out** — the
data is a nested tree, which is what TOON is worst at, and JSON has JCS (RFC 8785), which
matters the moment a charter is signed.

## Build order

The asset-reference sub-parser first; then lexer/parser/AST; then static rules and the error
catalogue; then the emitter; then the compiled form and evaluator. See
[`docs/handover-charter-parser.md`](docs/handover-charter-parser.md).

`mint://` and `unit://` are **one token decomposed by a real sub-parser**. Never `split('/')`
them — E401 has to underline the offending segment, which needs byte offsets inside the token.

## Git

- **`master`, never `main`.**
- One change per commit. Substantial work goes on a branch with a PR.
- **No AI attribution.** No `Co-Authored-By` trailers, no "Generated with" lines, anywhere.
- **No copyright, licence or SPDX banners in source.** Licensing lives in the manifest.

## Licence

Dual [Apache-2.0](LICENSE-APACHE) / [MIT](LICENSE-MIT). Contributions are taken under both.
