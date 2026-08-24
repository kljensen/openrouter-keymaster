# v0.1 release checklist

Every item names the command that settles it. An item is checked only when that
command has actually been run and gave the answer below — not when someone
believes it would.

Status as of the commit that adds this file.

| # | Item | Status |
| --- | --- | --- |
| 1 | [All milestone issues closed](#1-all-milestone-issues-closed) | ✓ |
| 2 | [ADRs accepted and reconciled with the code](#2-adrs-accepted-and-reconciled-with-the-code) | ✓ |
| 3 | [`just check` passes](#3-just-check-passes) | ✓ |
| 4 | [The live suite passes](#4-the-live-suite-passes) | ☐ **not yet executed** |
| 5 | [No secret plaintext in history, fixtures, or artifacts](#5-no-secret-plaintext-in-history-fixtures-or-artifacts) | ✓ |
| 6 | [CLI help and output reviewed as a compatibility surface](#6-cli-help-and-output-reviewed-as-a-compatibility-surface) | ✓ |
| 7 | [Dependency policy reviewed](#7-dependency-policy-reviewed) | ✓ |
| 8 | [License chosen](#8-license-chosen) | ☐ **open — owner decision** |
| 9 | [Version set to 0.1.0 and changelog written](#9-version-set-to-010-and-changelog-written) | ✓ |

Two items are open. Item 4 needs a dedicated test organization that does not
exist yet; item 8 is the repository owner's to decide. Neither is a defect, and
neither is quietly checked.

Items 1 and 3 were verified after the #20 commit landed: all twenty milestone
issues are closed, and CI run 32699016227 on commit `736941d` ran the full
battery online — including the `cargo deny` advisories check against a fresh
RustSec database — and succeeded.

---

## 1. All milestone issues closed

```sh
gh issue list --milestone v0.1 --state open --json number,title
```

**Expected:** empty once the issue that adds this file closes. Issues #1–#19 are
closed; #20 is this work.

## 2. ADRs accepted and reconciled with the code

```sh
grep -n '^- \*\*Status:\*\*' docs/adr/00*.md
grep -rn 'do not exist yet' docs/adr/
```

**Expected:** both ADRs read `Accepted`, and the second command finds nothing —
each ADR's *Implementation checks* section now names the modules and test files
that enforce it, rather than the issues that were going to.

Both were accepted through automated code review of the commit that introduced
them, which is what
[the ADR convention](adr/README.md#review) specifies for a single-maintainer
repository. Reconciling the checks list is a status change, not a change to an
accepted decision; the Context, Decision, Consequences, and Alternatives
sections are untouched.

## 3. `just check` passes

**Status: verified.** All five steps passed in CI run 32699016227 on commit
`736941d`, where `cargo deny` fetched a fresh advisory database. Locally the
same battery passes with `cargo deny --offline` on machines that cannot reach
the RustSec repository.

```sh
just check
```

Which is `cargo fmt --all -- --check`, `cargo check --locked --all-targets`,
`cargo clippy --locked --all-targets --all-features -- -D warnings`,
`cargo test --locked --all-features`, and
`cargo deny check advisories licenses bans sources` — exactly what CI runs.

**Expected:** every step exits 0.

**What was verified.** `cargo fmt --all -- --check`, `cargo check`, `cargo
clippy -- -D warnings`, and `cargo test --locked --all-features` all pass — the
test run is 19 binaries, zero failures, with the three live tests reported as
ignored.

**What is not.** `cargo deny` fetches the RustSec advisory database over the
network, which was unavailable. It was run as:

```sh
cargo deny --offline check advisories licenses bans sources
```

against the last locally fetched copy, and reported `advisories ok, bans ok,
licenses ok, sources ok`. That confirms licenses, bans, and sources, which do
not depend on the database — but it says nothing about advisories published
since that copy was fetched. Check this item after one online `just check`.
CI runs the online version on every push, so a green CI run on the release
commit also settles it.

The live suite is not in this battery and never will be. That it still compiles
is checked here, because `cargo check --all-targets` and `cargo test` build it:

```sh
cargo test --locked --test live --no-run
```

## 4. The live suite passes

```sh
just live
```

**Status: not yet executed.** This needs a dedicated OpenRouter test
organization with no inference credits and a management credential for it, and
no such organization exists yet. Running it against a shared organization is not
an acceptable substitute — the suite deletes every key carrying its run prefix,
and that filter is only survivable where there is nothing else to hit.

The suite is written, gated, and compiles on every build. What is unverified is
whether the production management API behaves the way the local harness assumes.
[`docs/live-tests.md`](live-tests.md) says what the first run needs and how to
clean up after it.

Check this item only after a real run against a real organization.

## 5. No secret plaintext in history, fixtures, or artifacts

Two questions, and they have different answers.

**Did a real credential ever get committed?** Every OpenRouter credential
carries the marker `sk-or-` — `sk-or-v1-` for an inference key, `sk-or-mgmt-`
for a management key — which is the same marker `redaction::looks_like_credential`
matches on. Scan for the family, case-insensitively, and list the distinct
literals rather than filtering with an exclusion list that can be wrong:

```sh
git grep -hoiE 'sk-or-[a-z0-9]+-[A-Za-z0-9_-]{4,}' $(git rev-list --all) -- . \
  | sort -u
```

**Expected:** every line is obviously a fake test constant, and a human reads
them to say so. Verified — ten literals, all fake:

```text
sk-or-mgmt-abc123
sk-or-mgmt-FAKEAMBIENTCREDENTIAL
sk-or-mgmt-FAKEFAKEFAKE
sk-or-v1-FAKEFAKEFAKE
sk-or-v1-KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE
sk-or-v1-leaked
sk-or-v1-LEAKEDFROMANAME
sk-or-v1-NOT-A-REAL-KEY
sk-or-v1-not-a-uuid
sk-or-v1-THE-PREVIOUS-KEY
```

**Where does the test sentinel appear?** It is a deliberately fake constant, so
finding it in test code is correct; finding it in a state file, a log, or an
artifact would not be.

```sh
git log --all --format='' --name-only \
  -S'KEYMASTER-SENTINEL-8f31c2-NEVER-DISCLOSE' | sort -u
```

**Expected:** only source, test, and documentation files. Verified — the eight
files are `tests/support/sentinel.rs`, which defines it; `src/config/tests.rs`,
`src/ids.rs`, `src/receiver/command.rs`, `src/receiver/file.rs`,
`src/receiver/mod.rs`, and `src/state/tests.rs`, which assert it is refused or
never disclosed; and this checklist, which quotes it in the command above. No
state file, fixture artifact, or log.

The runtime property — that no secret reaches stdout, stderr, JSON, state, a
temporary file, or a filename — is enforced by the sentinel scans in the test
suite, and is covered by item 3.

## 6. CLI help and output reviewed as a compatibility surface

```sh
cargo run -- --help
for command in plan apply status import rotate recover retire delete state; do
    cargo run -- help "$command"
done
```

**Expected:** every command in
[the README's command list](../README.md#commands) appears, spelled the same
way; the three global options are `--config`, `--state`, and `--json`; there is
**no** option for the management credential.

Reviewed. The surface itself, and the rules for changing it, are written down in
[`docs/compatibility.md`](compatibility.md#compatibility-surfaces): the command
tree, the option names, the exit codes, and the JSON field names and enumerated
values are contracts. Human-readable text is not.

## 7. Dependency policy reviewed

```sh
cargo deny check advisories licenses bans sources
cargo tree --depth 1
```

**Expected:** `cargo deny` passes. Every direct dependency is justified in a
comment in `Cargo.toml`, and the policy is
[in the README](../README.md#dependency-policy): committed `Cargo.lock`,
`--locked` everywhere, an allow-list of permissive licenses, no wildcard
requirements, crates.io as the only source.

`deny.toml` carries one narrow exception, for `webpki-root-certs`, whose Mozilla
CA bundle is published as data under CDLA-Permissive-2.0 rather than as code. It
is scoped to that crate and explained in place.

## 8. License chosen

**Status: open. This is the repository owner's decision and is not made here.**

The crate is `publish = false` and carries no license expression. `deny.toml`
holds the matching exception:

```toml
[licenses]
# Keymaster is an unpublished application; it carries no license expression yet.
private = { ignore = true }
```

That exception is what keeps `cargo deny check licenses` passing for the crate
itself while its own license is undecided; the allow-list still governs every
dependency.

Choosing a license means: add a `LICENSE` file, set `license` in `Cargo.toml`,
and remove `private = { ignore = true }` from `deny.toml` so the crate is held
to the same policy as everything else. Deciding to keep it unpublished and
unlicensed is also a decision — it just needs to be a deliberate one, recorded
here.

## 9. Version set to 0.1.0 and changelog written

```sh
grep '^version' Cargo.toml
head -20 CHANGELOG.md
```

**Expected:** `version = "0.1.0"` in `Cargo.toml`, and a `0.1.0` section in
[`CHANGELOG.md`](../CHANGELOG.md) summarizing the milestone. Both verified.

Note that a release tag should not be cut while items 4 and 8 are open. The
version is set so that what ships and what the changelog describes are the same
thing; tagging is the owner's call once the two open items are settled.
