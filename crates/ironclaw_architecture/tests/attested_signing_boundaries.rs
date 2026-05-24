//! Dependency-boundary tests for the attested-signing substrate.
//!
//! PR1 of the 10-PR attested-signing stack introduces
//! `ironclaw_signing_provider`, the provider-agnostic `SigningProvider` trait
//! crate. It pins the binding model every downstream crate (chain signing,
//! attestation, external wallets) depends on, so it MUST stay pure: zero chain,
//! crypto, or secrets dependencies. A regression that pulls any of those into
//! the trait crate would let chain-specific or key-handling code leak into the
//! shared abstraction and is caught here.
//!
//! See `docs/plans/2026-05-23-attested-signing-substrate.md`.

use std::collections::BTreeSet;
use std::process::Command;

use serde_json::Value;

/// The only normal dependencies allowed in the signing-provider trait crate.
/// Dev/build dependencies are excluded from this assertion.
const ALLOWED_NORMAL_DEPENDENCIES: &[&str] = &["async-trait", "serde", "thiserror"];

#[test]
fn signing_provider_trait_crate_has_no_chain_crypto_or_secrets_dependency() {
    let metadata = cargo_metadata();
    let packages = metadata["packages"]
        .as_array()
        .expect("cargo metadata must include packages");

    let package = packages
        .iter()
        .find(|package| package["name"] == "ironclaw_signing_provider")
        .expect(
            "ironclaw_signing_provider must be a workspace member; add it to the root \
             Cargo.toml `workspace.members` (see attested-signing PR1)",
        );

    let dependencies = package["dependencies"]
        .as_array()
        .expect("package dependencies must be an array");

    let normal_dependencies: BTreeSet<&str> = dependencies
        .iter()
        .filter(|dependency| dependency.get("kind").is_none_or(Value::is_null))
        .filter_map(|dependency| dependency["name"].as_str())
        .collect();
    let allowed_dependencies: BTreeSet<&str> =
        ALLOWED_NORMAL_DEPENDENCIES.iter().copied().collect();

    assert_eq!(
        normal_dependencies, allowed_dependencies,
        "ironclaw_signing_provider is the pure trait crate at the base of the attested-signing \
         stack and must carry exactly the approved normal dependencies. Dev/build dependencies \
         are excluded from this assertion.\n\
         Concrete chain/crypto types belong in ironclaw_attestation (PR2) and the chain crates, \
         not the trait crate. See docs/plans/2026-05-23-attested-signing-substrate.md.",
    );
}

fn cargo_metadata() -> Value {
    let manifest_path = workspace_root().join("Cargo.toml");
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(&manifest_path)
        .output()
        .unwrap_or_else(|error| panic!("failed to run cargo metadata: {error}"));

    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata output must be JSON")
}

fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("architecture crate must live under crates/ironclaw_architecture")
        .to_path_buf()
}
