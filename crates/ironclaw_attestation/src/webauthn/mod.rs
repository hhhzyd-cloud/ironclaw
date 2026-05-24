//! WebAuthn registry + verifier — the custodial-path approval layer.
//!
//! This is the security core of the custodial attested-signing path. A
//! registered passkey ([`registry`]) plus a fully-validated assertion
//! ([`verify`]) is what authorizes IronClaw to use a custody key for exactly
//! one signing operation.
//!
//! ## Why `webauthn-rs-core` (and not a hand-rolled verifier)
//!
//! WebAuthn assertion verification is security-critical and error-prone: COSE
//! key decoding, ECDSA(P-256)/EdDSA signature checks over
//! `authenticatorData ∥ SHA-256(clientDataJSON)`, and DER handling are exactly
//! the places a hand-rolled implementation introduces silent vulnerabilities.
//! We therefore delegate the *cryptographic* core to
//! [`webauthn_rs_core`] (`COSEKey::verify_signature`, the COSE key model — a
//! maintained, audited crate) while owning the *Relying-Party policy* checks
//! ourselves in [`verify`]. We deliberately do NOT adopt webauthn-rs's
//! `Webauthn`/session state model: that model imposes its own challenge
//! lifecycle, whereas our anti-replay nonce is the
//! [`crate::ChallengePreimage`] commitment from [`crate::challenge`]. Binding
//! OUR challenge as the expected challenge requires running the RP checks
//! ourselves. (`webauthn-rs-core` is MPL-2.0 — weak, per-file copyleft;
//! acceptable as an unmodified upstream dependency.)
//!
//! ## Fail-closed posture
//!
//! Every check in [`verify::verify_assertion`] is fail-closed: any failure
//! (missing UV, wrong type, challenge mismatch, rpIdHash mismatch, disallowed
//! origin, signCount regression, bad signature, foreign userHandle, unknown
//! credential) returns an `Err` and NO [`verify::VerifiedAssertion`] is
//! produced. A `VerifiedAssertion` can only exist after the full checklist
//! passed.

pub(crate) mod registry;
pub(crate) mod verify;

pub use registry::{
    Aaguid, AttestationPolicy, BackupFlagPolicy, BootstrapPolicy,
    InMemoryWebAuthnCredentialRegistry, OriginPolicy, RegisteredCredential, RegistrationError,
    RegistrationRequest, SignCountPolicy, WebAuthnCredentialRegistry,
};
pub use verify::{AssertionInput, VerificationError, VerifiedAssertion, verify_assertion};
