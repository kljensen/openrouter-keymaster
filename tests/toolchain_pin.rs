//! The pinned toolchain and the declared MSRV must be the same version.

const CARGO_TOML: &str = include_str!("../Cargo.toml");
const RUST_TOOLCHAIN_TOML: &str = include_str!("../rust-toolchain.toml");

/// Reads `key = "value"` from a small, hand-written TOML file.
fn string_field(toml: &str, key: &str) -> String {
    toml.lines()
        .filter_map(|line| line.trim().strip_prefix(key))
        .find_map(|rest| rest.trim_start().strip_prefix('='))
        .map(|value| value.trim().trim_matches('"').to_owned())
        .unwrap_or_else(|| panic!("`{key}` not found"))
}

#[test]
fn toolchain_channel_matches_rust_version() {
    assert_eq!(
        string_field(RUST_TOOLCHAIN_TOML, "channel"),
        string_field(CARGO_TOML, "rust-version"),
        "rust-toolchain.toml channel and Cargo.toml rust-version disagree"
    );
}
