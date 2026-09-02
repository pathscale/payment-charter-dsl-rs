# Handover: the Payment Charter DSL compiler

Date 2026-09-02. For whoever builds this. Written to be actionable without reading the
conversation it came from.

Build against [the spec](https://github.com/pathscale/payment-charter-dsl/blob/master/spec.md), which is normative. Design context, in order:
[`authoring-background.md`](https://github.com/pathscale/payment-charter-dsl/blob/master/docs/authoring-background.md) (what a controller
needs), [`language-comparison.md`](https://github.com/pathscale/payment-charter-dsl/blob/master/docs/language-comparison.md) (why not an existing
language), [`design.md`](https://github.com/pathscale/payment-charter-dsl/blob/master/design.md) (the grammar and semantics). This document is the
build instruction.

## What this is, in one paragraph

A financial controller needs to express spending policy — limits, velocities, approval
thresholds — without writing code. The enforcement engine
(`pays.online-core/crates/policy`, 552 lines) already couples durable state to signature
release and asserts an invariant over it. What is missing is everything between a person and
that engine: a document format, a schema, a validator that rejects anything the engine cannot
bound, and a compiler down to the engine's primitives.

## Decisions already made — do not relitigate without new information

1. **The interchange format is a structured document, not text.** The UI builds a typed
   object; JSON on the wire. A text syntax may exist later for humans who want to read and
   diff policies in git, but nothing depends on it and it is not in scope here.
2. **No parser in TypeScript.** The browser builds the object with types and JSON Schema; the
   backend validates. Whole-policy checks are a round trip, which is fine for an operation a
   controller performs rarely. Rejected: compiling a Rust validator to wasm.
3. **We write the evaluator; we do not embed Rego.** Regorus (Rust, `no_std`, musl-tested) is
   the escape hatch if the vocabulary must ever open. It is not the starting point, because
   the enclave's whole argument is that it is small enough to read.
4. **Catala's semantics, not Catala.** A value has a base definition and prioritised
   exceptions, and **ambiguity is an error, never a silent pick.** That is the one borrowed
   idea. Do not adopt the compiler.
5. **The vocabulary is closed.** Adding a field is an engine change under review, never
   something an author can do. This is what keeps the invariant statable.

## Scope

**In:** the document schema, a validator, the bound extractor, the compiler to engine
primitives, and tests.

**Out:** the UI, the text syntax, the registry service, and any change to the enforcement
state machine beyond the new primitives listed below.

## The data model

Two compositions, and conflating them is the most likely design error:

- **Limits are conjunctive.** Several limits all apply; each can refuse; none disables
  another. Adding a limit can only tighten a policy.
- **A limit's *value* has exceptions.** This is where prioritised defaults apply — to the
  ceiling, not to whether the rule runs.

A limit carries: a dimension (`amount` with an asset, or `count`), a window (rolling seconds,
or fixed day/week/month/year with a timezone), a scope key for accumulation (account, agent,
instrument, counterparty), an optional escalation threshold with a quorum, and an ordered set
of exceptions, each a condition plus a literal value or `deny`.

Conditions are built from a **closed** field set: counterparty, category, asset, asset class,
provenance, date. Operators: is, is not, in, not in, before, after, and/or/not.

Assets are fully-qualified references, never tickers:

```
mint://USDC/Circle/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp
unit://USD/ISO-4217
```

Every segment verifies against the registry; a mismatch is an error naming the disagreement.
`unit://` denominated limits require a signed rate and fail closed without one. The policy
pins the registry it was authored against.

## What the validator must guarantee

This is the part that earns its existence. The engine's invariant — *no execution releases
signatures whose aggregate exposure exceeds the policy's limits over any window* — is only
provable if the policy names something finite. The validator is what makes that true.

**Reject unless all of these hold:**

1. **Exception values are literals.** Never expressions, never arithmetic, never a reference
   to another value. This is what makes the ceiling set finite and readable from the source.
2. **Conditions cannot reference accumulated state.** A condition selects *which* ceiling
   applies from request attributes. It must not ask how much has been spent, or the ceiling
   becomes a function of the thing it bounds.
3. **No construct removes or disables a limit.**
4. **Overlapping exceptions are resolved or rejected.** Where two exception conditions can be
   shown to overlap — intersecting date ranges, groups sharing a member, one condition
   subsuming another — reject and name both rules. Where overlap cannot be decided
   statically, a runtime conflict denies the payment.
5. **Every asset reference resolves** in the pinned registry, with every segment matching.
6. **A `unit://` limit declares a rate source and a staleness bound.**

**And emit:** the static ceiling for each limit — the maximum value it can ever resolve to,
which is the largest literal in its base-plus-exceptions set. A policy whose bound cannot be
computed does not compile. `check_invariant` consumes this.

## The engine today is a placeholder

`pays.online-core/crates/policy` is not a thing to extend. It is a hardcoded stand-in for a
policy, written before there was a document format: eight scalar fields, set from environment
variables, with the rules baked into Rust.

**The correct design is that the DSL is the specification and the engine reads it.** The engine
holds durable state, evaluates a compiled policy against it, and releases or refuses a
signature. It does not know what a limit is called or how many there are. Every field the
placeholder hardcodes — the caps, the tiers, the single window — becomes data.

So the order is: **settle the semantics, write the parser, then rewrite the engine against
it.** Do not spend effort adding count limits or calendar windows to the placeholder. They are
not primitives to bolt on; they are consequences of the document format, and adding them
piecemeal to code that is going to be replaced buys nothing.

What survives from the placeholder is the part that was never about policy: the reservation
state machine, the exposure ledger, the hash-chained journal, and `check_invariant`. That
machinery is right. It is the schema of the thing it enforces that was provisional.

One item there is worth carrying forward as a *requirement*, not a fix: `per_tx_cap: u64` and
`window_cap: u64` have no asset, while `Intent` carries `asset: [u8; 32]`. A cap of 500
currently means 500 of anything, and exposure sums across incommensurable units. The
replacement must key every accumulator by asset. Do not patch the placeholder to do it.

## Where the code goes

**Two crates, not one.** The enclave never parses text — it evaluates a compiled policy.
That splits the dependency constraint, which the earlier version of this document
over-applied to both halves.

- **`pays-policy`** — the compiled form and the evaluator. Dependency-free in the same way
  the rest of the core is, because this is what links into the enclave. It must not depend
  on the enclave protocol or on any chain crate.
- **`pays-charter`** — lexer, parser, static rules, resolver checks, diagnostics.
  Runs in the backend and the CLI, never in the enclave, so it MAY take dependencies where
  they earn their place. It depends on `pays-policy` to emit the compiled form.

The conformance suite runs against both: `parse/` and `canonical/` exercise the compiler,
`eval/` exercises the evaluator.
## Tests that must exist

Follow the house pattern: the interesting content is the refusals.

- A policy with two overlapping exceptions is **rejected**, and the error names both.
- An exception with a computed value is **rejected**.
- A condition referencing accumulated spend is **rejected**.
- An asset reference whose symbol and mint disagree is **rejected**, naming the mismatch.
- A `unit://` limit with no rate source is **rejected**.
- An unknown mint **fails closed** rather than being permitted by omission.
- The extracted ceiling equals the largest literal, over a generated set of policies.
- A policy compiled, evaluated, and re-evaluated against the same pinned registry gives an
  identical decision — the reproducibility property the dispute story depends on.

## Open questions, and how to decide them

- **Explicit priority on exceptions, or force disjoint conditions always?** Forcing
  disjointness is stricter and probably right first; it can be relaxed later without breaking
  existing policies, while the reverse cannot.
- **Money representation.** Minor units as integers, with decimals from the mint rather than
  assumed. Decide the rounding direction now, and make it always tighten.
- **Is `deny` an exception value or its own rule form?** It reads well as a value; it is not a
  ceiling, which argues the other way.
- **Fixed-window alignment when a policy changes mid-window.** Does the window restart, or
  does the new ceiling apply to the accumulated total? The second is safer and harder to
  explain.
- **Token program as a URI segment, or supplied by the registry?** Probably the registry,
  since it is a fact about the mint rather than an authoring choice. But
  `pays-solana-deposit` already treats Token versus Token-2022 as significant, so it must
  come from somewhere.

## What this is not blocking, and what is

This work blocks no deadline, and the paper does not reference it. The product's live blocker
is that **nothing can complete a payment** — the API authorises and submits nothing.

Within this work, the order is strict and the first step is not code: **the semantics have to
be settled before the parser is worth writing**, because the parser cannot decide what a
window boundary means or whether a reservation holds cap. See the open list in
[`design.md`](https://github.com/pathscale/payment-charter-dsl/blob/master/design.md).
