# Must match `tool: cargo-deny@…` in .github/workflows/ci.yml.
cargo_deny_version := "0.20.2"

default: check

# Format all code.
fmt:
    cargo fmt --all

# Lint all targets; warnings are errors.
lint:
    cargo clippy --locked --all-targets --all-features -- -D warnings

# Run all tests.
test:
    cargo test --locked --all-features

# Fail unless the local cargo-deny matches the version CI pins.
check-deny-version:
    @cargo deny --version | grep -qF "cargo-deny {{cargo_deny_version}}" || \
        { echo "error: cargo-deny {{cargo_deny_version}} required (CI pin);" \
               "install with: cargo install cargo-deny --version {{cargo_deny_version}} --locked"; exit 1; }

# The same battery CI runs.
check: check-deny-version
    cargo fmt --all -- --check
    cargo check --locked --all-targets
    cargo clippy --locked --all-targets --all-features -- -D warnings
    cargo test --locked --all-features
    cargo deny check advisories licenses bans sources
