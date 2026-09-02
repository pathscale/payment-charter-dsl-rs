@AGENTS.md

# Claude Code notes — payment-charter-dsl-rs

The import above is binding: [`AGENTS.md`](AGENTS.md) is the **working agreement** for this
repository, and every Claude Code session loads it automatically. Don't copy rules here —
one source of truth, no drift. Only genuinely Claude-specific wiring belongs below.

- `cargo` is not on `PATH` by default here; `/opt/homebrew/opt/rustup/bin` has to be exported
  onto `PATH` first. The absolute path to the binary alone is not enough.
