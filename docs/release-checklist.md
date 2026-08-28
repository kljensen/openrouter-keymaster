# v0.3 release checklist

Every item names the command that settles it. An item is checked only when that
command has actually been run and gave the answer below — not when someone
believes it would.

Status as of the commit that closes the v0.3 milestone. The v0.1 checklist this
replaces is in the history; where an item has not changed since, it says so
rather than repeating the work.

| # | Item | Status |
| --- | --- | --- |
| 1 | [All milestone issues closed](#1-all-milestone-issues-closed) | ✓ |
| 2 | [ADRs accepted and reconciled with the code](#2-adrs-accepted-and-reconciled-with-the-code) | ✓ |
| 3 | [`just check` passes](#3-just-check-passes) | ✓ |
| 4 | [The live suite passes](#4-the-live-suite-passes) | ✓ |
| 5 | [No secret plaintext in history, fixtures, or artifacts](#5-no-secret-plaintext-in-history-fixtures-or-artifacts) | ✓ |
| 6 | [CLI help and output reviewed as a compatibility surface](#6-cli-help-and-output-reviewed-as-a-compatibility-surface) | ✓ |
| 7 | [Dependency policy reviewed](#7-dependency-policy-reviewed) | ✓ |
| 8 | [License chosen](#8-license-chosen) | ✓ |
| 9 | [Changelog written and the version decided](#9-changelog-written-and-the-version-decided) | ✓ |

No items are open. Item 4 was the last, and it closed on 2026-08-28: `just
live` passed 7 of 7 against a real organization, four runs in a row, over
`cbd5923..70cc0b5`.

---

## 1. All milestone issues closed

```sh
gh issue list --milestone v0.3 --state open --json number,title
```

**Expected:** empty once the issue that adds this file closes. #31, #32, #33,
#34, and #35 are closed; #36 is this work.

## 2. ADRs accepted and reconciled with the code

```sh
grep -n '^- \*\*Status:\*\*' docs/adr/0*.md
grep -rn 'do not exist yet' docs/adr/
```

**Expected:** all six ADRs read `Accepted`, and the second command finds
nothing. Verified.

ADR-0004, ADR-0005, and ADR-0006 were accepted in this commit, each through
automated code review of the commits that implement it — which is what
[the ADR convention](adr/README.md#review) specifies for a single-maintainer
repository — and each gained an *Implementation checks* section naming the
modules and tests that enforce it, and saying plainly what those checks cannot
reach. For all three that is the same thing: the real API. See item 4.

Reconciling the checks list is a status change, not a change to an accepted
decision; the Context, Decision, Consequences, and Alternatives sections are
untouched.

## 3. `just check` passes

**Status: verified on this commit**, locally, with the **online** `cargo deny`:
all six steps exited 0 and the advisories check reported `advisories ok, bans
ok, licenses ok, sources ok` against a database it fetched itself. That is the
one thing the v0.1 checklist could only get from CI.

```sh
just check
```

Which is `cargo fmt --all -- --check`, `cargo check --locked --workspace
--all-targets`, `cargo check --locked --package openrouter-keymaster-core
--all-targets`, `cargo clippy --locked --workspace --all-targets --all-features
-- -D warnings`, `cargo test --locked --workspace --all-features`, and
`cargo deny check advisories licenses bans sources` — exactly what CI runs.

**Expected:** every step exits 0. The test run is 27 binaries: 722 passed, 0
failed, 8 ignored — the seven live tests and one long-running client case.

CI was last green on `4791380`, the commit before this one (run 33131560738).
A green CI run on the release commit settles this item again from a machine
that is not the author's.

The live suite is not in this battery and never will be. That it still compiles
is checked here, because `cargo check --all-targets` and `cargo test` build it:

```sh
cargo test --locked --test live --no-run
```

## 4. The live suite passes

```sh
just live
```

**Status: passed 2026-08-28**, against a dedicated OpenRouter test
organization, on commits `cbd5923..70cc0b5`. Four consecutive runs, each 7 of 7
scenarios, the last on `70cc0b5`. Nothing in the suite is asserted from
OpenRouter's documentation alone any more: workspace create and delete, the
budget `PUT`, every log destination request, and the analytics vocabulary have
all been sent for real.

Two API rules the runs surfaced, neither of them in the OpenAPI document:

- `POST /guardrails` rejects `limit_usd = 0` with a 400, "Too small: expected
  number to be >0". This stopped four of seven scenarios on the first run. The
  guardrail fixtures now ask for one cent and the validator rejects a zero
  guardrail budget offline.
- An unscoped `GET /keys` or `GET /guardrails` answers for the Default workspace
  and no other, and `include_disabled` does not change it. A snapshot now reads
  once unscoped and once per workspace it found, and the sweep does the same.

The budget `PUT` was **accepted** on the tested account, though budgets are
documented as Enterprise, and OpenRouter accepted the unreachable
`https://example.invalid/…` webhook URL at create time.

Every one of those four runs left its guardrails behind — `alpha`, `beta`,
`gamma`, and `cap` in the Default workspace — which had to be removed by hand
with `DELETE /guardrails/{id}`, 200 each. The sweep now deletes them itself
(#37); that is a change to the suite, not a change to what the runs proved.

Re-running this needs the same thing it always did: a dedicated test
organization with no inference credits and a management credential for it.
Running it against a shared organization is not an acceptable substitute — the
suite deletes every key, guardrail, log destination, and workspace carrying its
run prefix, and that filter is only survivable where there is nothing else to
hit. [`docs/live-tests.md`](live-tests.md) says what a run needs, what it found,
and how to clean up after one that crashed.

## 5. No secret plaintext in history, fixtures, or artifacts

Two questions, and they have different answers.

**Did a real credential ever get committed?** Every OpenRouter credential
carries the marker `sk-or-`, and what follows it says nothing about which kind
it is: a management key carries the same `sk-or-v1-` shape an inference key
does. That marker is what `redaction::looks_like_credential` matches on. Scan
for the family, case-insensitively, and list the distinct literals rather than
filtering with an exclusion list that can be wrong:

```sh
git grep -hoiE 'sk-or-[a-z0-9]+-[A-Za-z0-9_-]{4,}' $(git rev-list --all) -- . \
  | sort -u
```

**Expected:** every line is obviously a fake test constant, and a human reads
them to say so. `sk-or-mgmt-` is not a real prefix; the `mgmt` literals are
fixtures proving the marker match does not depend on what follows it, and
earlier spellings of the fake management credentials, still in history.
Verified — fifteen literals, all fake:

```text
sk-or-mgmt-abc123
sk-or-mgmt-FAKEAMBIENTCREDENTIAL
sk-or-mgmt-FAKEFAKEFAKE
sk-or-v1-A-DIFFERENT-FAKE-CREDENTIAL
sk-or-v1-deadbeef
sk-or-v1-FAKEAMBIENTCREDENTIAL
sk-or-v1-FAKEFAKEFAKE
sk-or-v1-FAKEMANAGEMENTCREDENTIAL
sk-or-v1-KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE
sk-or-v1-leaked
sk-or-v1-LEAKEDFROMANAME
sk-or-v1-NOT-A-REAL-KEY
sk-or-v1-not-a-uuid
sk-or-v1-PUBLIC-API-TEST-NEVER-A-REAL-CREDENTIAL
sk-or-v1-THE-PREVIOUS-KEY
```

Three are new since v0.1. `sk-or-v1-A-DIFFERENT-FAKE-CREDENTIAL`, which
`crates/cli/tests/ops.rs` uses to prove a plan fingerprint refuses an apply made
with a different credential. `sk-or-v1-PUBLIC-API-TEST-NEVER-A-REAL-CREDENTIAL`,
which `crates/core/tests/public_api.rs` uses because it compiles against the
public surface only and cannot reach the shared sentinel. And
`sk-or-v1-deadbeef`, in `crates/core/src/config/tests.rs`, which is deliberately
the one shape a slug check would otherwise let through: lowercase alphanumeric
segments separated by single hyphens.

**Where does the test sentinel appear?** It is a deliberately fake constant, so
finding it in test code is correct; finding it in a state file, a log, or an
artifact would not be.

```sh
git grep -l 'KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE' HEAD
git log --all --format='' --name-only \
  -S'KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE' | sort -u
```

**Expected:** only source, test, and documentation files. Verified — nine in the
current tree: `crates/core/src/test_support/sentinel.rs`, which defines it;
`crates/core/src/config/tests.rs`, `crates/core/src/ids.rs`,
`crates/core/src/receiver/caller.rs`, `crates/core/src/receiver/command.rs`,
`crates/core/src/receiver/file.rs`, `crates/core/src/receiver/mod.rs`, and
`crates/core/src/state/tests.rs`, which assert it is refused or never disclosed;
and this checklist, which quotes it in the command above. The history search
finds the same set under the pre-workspace-split paths, and no state file,
fixture artifact, or log.

The runtime property — that no secret reaches stdout, stderr, JSON, state, a
temporary file, or a filename — is enforced by the sentinel scans in the test
suite, and is covered by item 3. The `caller` receiver is scanned the same way,
including the report a host is handed back.

## 6. CLI help and output reviewed as a compatibility surface

```sh
cargo run -- --help
for command in plan apply status spend import rotate recover retire \
               decommission delete state; do
    cargo run -- help "$command"
done
```

**Expected:** every command in
[the command list](commands.md#the-command-tree) appears, spelled the same
way; the four global options are `--config`, `--state`, `--workspace`, and
`--json`; there is **no** option for the management credential.

Reviewed on this commit. The tree is eleven commands; `import` and `delete`
carry the four and three resource subcommands the reference lists, spelled
`log-destination` in both. The surface itself, and the rules for changing it,
are written down in
[`docs/compatibility.md`](compatibility.md#compatibility-surfaces): the command
tree, the option names, the exit codes, and the JSON field names and enumerated
values are contracts. Human-readable text is not.

## 7. Dependency policy reviewed

```sh
cargo deny check advisories licenses bans sources
cargo tree --workspace --depth 1
```

**Expected:** `cargo deny` passes, which item 3 ran online on this commit. Every
direct dependency is justified in a comment in the crate's `Cargo.toml`, and the
policy is [in `CONTRIBUTING.md`](../CONTRIBUTING.md#dependency-policy): committed
`Cargo.lock`, `--locked` everywhere, an allow-list of permissive licenses, no
wildcard requirements, crates.io as the only source. No dependency was added in
this milestone.

`deny.toml` carries one narrow exception, for `webpki-root-certs`, whose Mozilla
CA bundle is published as data under CDLA-Permissive-2.0 rather than as code. It
is scoped to that crate and explained in place.

## 8. License chosen

**Status: verified**, unchanged since v0.1. The owner chose the Unlicense on
2026-08-24.

```sh
grep -n '^license' Cargo.toml && head -1 LICENSE && cargo deny check licenses
```

**Expected:** `license = "Unlicense"` under `[workspace.package]`, which both
crates inherit, a `LICENSE` file beginning "This is free and unencumbered
software released into the public domain", and a passing license check with no
private-crate exception in `deny.toml`. `publish = false` stays: publishing to
crates.io is a separate decision from licensing.

## 9. Changelog written and the version decided

```sh
grep '^version' Cargo.toml
sed -n '/## \[0.3.0\]/,/## \[0.1.0\]/p' CHANGELOG.md
```

**Status: verified.** `[workspace.package] version = "0.3.0"`, and everything
since 0.1.0 — the workspace scope, the `caller` receiver, workspaces, log
destinations, `spend`, and this milestone's live scenarios and documentation —
is the `[0.3.0] - 2026-08-28` section of [`CHANGELOG.md`](../CHANGELOG.md),
with `Unreleased` empty above it. The number skips 0.2.0 because nothing was
tagged between 0.1.0 and now; the v0.2 milestone's work ships in 0.3.0.
v0.1.0 was never tagged either, so the changelog links `[0.1.0]` to the commit
that finalized it and compares `[0.3.0]` from there. The tag is `v0.3.0`.
