# Must match `tool: cargo-deny@…` in .github/workflows/ci.yml.
cargo_deny_version := "0.20.2"

default: check

# Format all code.
fmt:
    cargo fmt --all

# Lint all targets; warnings are errors.
lint:
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

# Run all tests.
test:
    cargo test --locked --workspace --all-features

# Fail unless the local cargo-deny matches the version CI pins.
check-deny-version:
    @cargo deny --version | grep -qF "cargo-deny {{cargo_deny_version}}" || \
        { echo "error: cargo-deny {{cargo_deny_version}} required (CI pin);" \
               "install with: cargo install cargo-deny --version {{cargo_deny_version}} --locked"; exit 1; }

# Opt-in acceptance tests against a real OpenRouter organization.
#
# NOT part of `check` and never run in CI. It creates and deletes real
# resources with a real management credential, so it needs a dedicated test
# organization with no inference credits, `OPENROUTER_MANAGEMENT_KEY` exported
# for it, and docs/live-tests.md read first. FILTER narrows it to one test.
live filter='':
    KEYMASTER_LIVE_TESTS=1 cargo test --locked --test live -- --ignored --test-threads=1 {{filter}}

# Delete what a crashed live run left behind. PREFIX is the run identifier,
# which is the name of its journal file in target/live-runs/.
live-sweep prefix:
    KEYMASTER_LIVE_TESTS=1 KEYMASTER_LIVE_SWEEP={{prefix}} \
        cargo test --locked --test live -- --ignored --exact live_sweep_named_prefix

# Token Fund issue #12.  Unlike `live`, this deliberately never lists or
# prefix-sweeps an account: it deletes only IDs it wrote to its 0600 journal.
# Supply the two current model slugs and export the management credential
# outside shell history; read docs/issue12-live-test.md before running.
issue12-live:
    KEYMASTER_ISSUE12_LIVE=1 cargo test --locked --test issue12_live -- --ignored --exact live_issue12_controls --test-threads=1

# Exact-ID recovery for a prior issue #12 journal.  PATH is a journal file,
# not a run prefix; it refuses a different OPENROUTER_BASE_URL.
issue12-live-recover path:
    KEYMASTER_ISSUE12_LIVE=1 KEYMASTER_ISSUE12_RECOVER={{path}} \
        cargo test --locked --test issue12_live -- --ignored --exact live_issue12_recover_exact_journal --test-threads=1

# The same battery CI runs.
check: check-deny-version
    cargo fmt --all -- --check
    cargo check --locked --workspace --all-targets
    cargo check --locked --package openrouter-keymaster-core --all-targets
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
    cargo test --locked --workspace --all-features
    cargo deny check advisories licenses bans sources
