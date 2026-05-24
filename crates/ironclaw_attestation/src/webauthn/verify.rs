//! WebAuthn assertion verifier — the full Relying-Party (RP) validation.
//!
//! [`verify_assertion`] performs the complete RP checklist, fail-closed on any
//! failure. The leaf cryptographic signature check is delegated to the
//! pure-Rust [`crate::webauthn::cose`] layer (`p256` for ES256, `ed25519-dalek`
//! for EdDSA, `coset` for COSE_Key parsing — no openssl); every *policy* check
//! is owned here so we can bind OUR [`crate::ChallengePreimage`] commitment as
//! the expected challenge (see [`crate::webauthn`] module docs for why).
//!
//! ## RP validation checklist (all enforced, all fail-closed)
//!
//! 1. **Credential is registered** for the expected user (`allowCredentials` /
//!    userHandle ownership binding).
//! 2. **`clientDataJSON.type == "webauthn.get"`** (assertion, not creation).
//! 3. **Echoed challenge equals our issued commitment** (anti-replay; the
//!    commitment is over the full [`crate::ChallengePreimage`]).
//! 4. **Origin (and topOrigin) pass the [`OriginPolicy`]**.
//! 5. **`rpIdHash` == SHA-256(rp_id)** from `authenticatorData`.
//! 6. **User Verification (UV) bit set** — not merely User Presence (UP). UP is
//!    also required (UV without UP is malformed).
//! 7. **Backup-eligibility / backup-state (BE/BS) flag policy** holds.
//! 8. **signCount regression handling** via [`SignCountPolicy`]
//!    (cloned-authenticator detection).
//! 9. **Signature verifies** over `authenticatorData ∥ SHA-256(clientDataJSON)`
//!    against the registered COSE public key.
//!
//! Only after ALL pass is a [`VerifiedAssertion`] produced; it carries the new
//! sign count the call site must persist (atomically with challenge-consume +
//! gate resolution in PR5).

use serde::Deserialize;
use sha2::{Digest, Sha256};

use ironclaw_signing_provider::{ApprovedTxHash, GateRef, UserId};

use crate::challenge::{ChallengeCommitment, ConsumedChallenge, CredentialId};
use crate::webauthn::registry::{
    OriginContext, OriginPolicy, RegisteredCredential, SignCountPolicy, WebAuthnCredentialRegistry,
};

/// Authenticator-data flag bits (WebAuthn / CTAP2).
mod flags {
    /// User Present.
    pub(super) const UP: u8 = 1 << 0;
    /// User Verified.
    pub(super) const UV: u8 = 1 << 2;
    /// Backup Eligible.
    pub(super) const BE: u8 = 1 << 3;
    /// Backup State.
    pub(super) const BS: u8 = 1 << 4;
}

/// Raw assertion material presented by the client, plus the verification
/// context the RP supplies.
pub struct AssertionInput<'a> {
    /// The user the flow expects to be authenticating (from the gated request).
    pub expected_user: &'a UserId,
    /// The userHandle returned by the authenticator (may be `None` for
    /// non-resident keys). When present it MUST match the expected user.
    pub user_handle: Option<&'a [u8]>,
    /// Credential id from the assertion (selected from `allowCredentials`).
    pub credential_id: &'a CredentialId,
    /// Raw `authenticatorData` bytes.
    pub authenticator_data: &'a [u8],
    /// Raw `clientDataJSON` bytes.
    pub client_data_json: &'a [u8],
    /// Raw assertion signature (DER for ES256, raw for EdDSA — as produced by
    /// the authenticator).
    pub signature: &'a [u8],
    /// The RP id this verification is scoped to.
    pub rp_id: &'a str,
    /// The consumed challenge whose commitment must equal the echoed challenge.
    pub consumed_challenge: &'a ConsumedChallenge,
    /// Mapping of the expected user's stable handle bytes, used to validate the
    /// `user_handle` echo when present.
    pub expected_user_handle: &'a [u8],
}

/// A sealed, fully-validated assertion. Existence of this value is proof the
/// entire RP checklist passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// The user the assertion authenticated.
    pub user: UserId,
    /// The credential id that signed.
    pub credential_id: CredentialId,
    /// The new sign count the call site must persist (>= previous).
    pub new_sign_count: u32,
    /// Whether the backup-state bit was set (carried for the call site /
    /// audit).
    pub backup_state: bool,
    /// The gate this assertion authorized, bound from the consumed challenge
    /// preimage. Carried out as proof of THIS gate so the gate-resolution step
    /// (PR5) resolves exactly the gate the user was challenged on — not a
    /// caller-supplied value.
    pub gate_ref: GateRef,
    /// The approved-transaction binding hash from the consumed preimage (PR2).
    /// Carried out as proof of THIS exact transaction so the signing step signs
    /// only the bytes the user approved.
    pub rendered_tx_digest: ApprovedTxHash,
}

/// Fail-closed verification errors. Each maps to a specific RP check.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerificationError {
    /// No credential registered for `(user, credential_id)`.
    #[error("credential not registered for this user")]
    UnknownCredential,

    /// `clientDataJSON` was not valid UTF-8 / JSON.
    #[error("malformed clientDataJSON: {reason}")]
    MalformedClientData {
        /// Non-secret parse-error description.
        reason: String,
    },

    /// `clientDataJSON.type` was not `webauthn.get`.
    #[error("clientDataJSON.type is not webauthn.get")]
    WrongClientDataType,

    /// The echoed challenge did not equal our issued commitment.
    #[error("challenge mismatch")]
    ChallengeMismatch,

    /// Origin / topOrigin failed the origin policy.
    #[error("origin rejected: {reason}")]
    OriginRejected {
        /// Non-secret rejection reason.
        reason: String,
    },

    /// `authenticatorData` was shorter than the fixed 37-byte header.
    #[error("authenticatorData too short")]
    AuthenticatorDataTooShort,

    /// `rpIdHash` did not match `SHA-256(rp_id)`.
    #[error("rpIdHash mismatch")]
    RpIdHashMismatch,

    /// User Presence (UP) bit was not set.
    #[error("user-presence (UP) bit not set")]
    UserPresenceMissing,

    /// User Verification (UV) bit was not set (UP alone is insufficient).
    #[error("user-verification (UV) bit not set")]
    UserVerificationMissing,

    /// BE/BS flag policy violation (e.g. BS set while BE clear is invalid).
    #[error("backup-flag policy violation: {reason}")]
    BackupFlagPolicy {
        /// Non-secret reason.
        reason: String,
    },

    /// signCount regressed (or otherwise failed the sign-count policy):
    /// possible cloned authenticator.
    #[error("signCount policy violation: {reason}")]
    SignCountPolicy {
        /// Non-secret reason.
        reason: String,
    },

    /// The userHandle returned by the authenticator did not match the expected
    /// user (foreign-credential / cross-account binding failure).
    #[error("userHandle does not match expected user")]
    ForeignUserHandle,

    /// A caller-supplied verification input did not match the corresponding
    /// field bound into the consumed challenge preimage. The assertion context
    /// is not the one that was authorized — fail closed.
    #[error("assertion context does not match the consumed challenge preimage: {field}")]
    PreimageContextMismatch {
        /// Which bound field mismatched (non-secret field name).
        field: &'static str,
    },

    /// The signature did not verify against the registered public key.
    #[error("assertion signature verification failed")]
    BadSignature,

    /// An internal error during signature verification.
    #[error("signature verification error: {reason}")]
    VerificationInternal {
        /// Non-secret description.
        reason: String,
    },
}

/// Minimal `clientDataJSON` shape we validate. Extra fields are ignored; the
/// fields we *require* are explicit.
#[derive(Deserialize)]
struct CollectedClientData {
    #[serde(rename = "type")]
    type_: String,
    /// base64url(no pad) of the challenge bytes the client received.
    challenge: String,
    origin: String,
    #[serde(rename = "topOrigin")]
    top_origin: Option<String>,
    /// `crossOrigin` is OPTIONAL in the serialization; absent ⇒ `false`.
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

/// Strict base64url (no padding) decode to bytes, fail-closed.
///
/// Rejects:
/// - any non-alphabet byte (incl. `=` padding — this is the no-pad form),
/// - a length ≡ 1 (mod 4), which cannot encode whole bytes,
/// - non-canonical trailing bits (the leftover `nbits` after the last full
///   byte MUST be zero, so each input has exactly one canonical encoding).
fn b64url_decode(s: &str) -> Result<Vec<u8>, VerificationError> {
    fn malformed(reason: &str) -> VerificationError {
        VerificationError::MalformedClientData {
            reason: reason.to_string(),
        }
    }
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    // A base64 group is 4 chars -> 3 bytes; a trailing group of length 1 is
    // impossible (it would carry only 6 bits, less than one byte).
    if bytes.len() % 4 == 1 {
        return Err(malformed("invalid base64url length in challenge"));
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    for &c in bytes {
        let v = val(c).ok_or_else(|| malformed("invalid base64url in challenge"))? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    // Canonical-encoding check: any leftover bits beyond the last whole byte
    // MUST be zero, otherwise this is a non-canonical (malleable) encoding.
    if nbits > 0 && (acc & ((1 << nbits) - 1)) != 0 {
        return Err(malformed("non-canonical trailing bits in challenge"));
    }
    Ok(out)
}

/// Constant-time-ish equality for the challenge commitment comparison. The
/// commitment is public, but we avoid early-return data-dependent timing as a
/// matter of hygiene.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Perform the full WebAuthn RP validation. Returns a [`VerifiedAssertion`]
/// only if every check passes.
pub fn verify_assertion(
    registry: &dyn WebAuthnCredentialRegistry,
    origin_policy: &dyn OriginPolicy,
    sign_count_policy: &dyn SignCountPolicy,
    input: &AssertionInput<'_>,
) -> Result<VerifiedAssertion, VerificationError> {
    // 0. Bind the assertion context to the consumed challenge preimage.
    //
    // The preimage (produced when WE issued the challenge) is the source of
    // truth for WHO is authenticating, WHICH credential answers, the RP id, and
    // the expected origin. The caller-supplied verification inputs are only
    // *claims*; every one must equal the corresponding bound field or we fail
    // closed BEFORE doing any signature work. This prevents a caller from
    // verifying an assertion against a gate/tx other than the one the user was
    // actually challenged on. `gate_ref` and `rendered_tx_digest` are then
    // carried into the success output as proof of THIS gate/tx.
    let preimage = &input.consumed_challenge.preimage;
    if input.expected_user != &preimage.user {
        return Err(VerificationError::PreimageContextMismatch { field: "user" });
    }
    if input.credential_id != &preimage.credential_id {
        return Err(VerificationError::PreimageContextMismatch {
            field: "credential_id",
        });
    }
    if input.rp_id != preimage.rp_id {
        return Err(VerificationError::PreimageContextMismatch { field: "rp_id" });
    }

    // 1. Credential must be registered for the expected user.
    let credential: RegisteredCredential = registry
        .lookup(&preimage.user, &preimage.credential_id)
        .ok_or(VerificationError::UnknownCredential)?;

    // userHandle ownership binding: when the authenticator returns a userHandle
    // it MUST match the expected user's handle. A foreign handle is rejected.
    if let Some(handle) = input.user_handle
        && !ct_eq(handle, input.expected_user_handle)
    {
        return Err(VerificationError::ForeignUserHandle);
    }

    // 2. Parse + validate clientDataJSON.
    let client_data: CollectedClientData =
        serde_json::from_slice(input.client_data_json).map_err(|e| {
            VerificationError::MalformedClientData {
                reason: e.to_string(),
            }
        })?;

    if client_data.type_ != "webauthn.get" {
        return Err(VerificationError::WrongClientDataType);
    }

    // 3. Echoed challenge must equal our issued commitment.
    let echoed = b64url_decode(&client_data.challenge)?;
    let expected: &ChallengeCommitment = &input.consumed_challenge.preimage.commitment();
    if !ct_eq(&echoed, expected.as_bytes()) {
        return Err(VerificationError::ChallengeMismatch);
    }

    // 4. Origin binding + policy. The asserted origin must equal the origin
    //    bound into the preimage (the origin the challenge was issued for); a
    //    different origin is a preimage-context mismatch, failing closed before
    //    the injectable policy even runs. The policy then additionally vets the
    //    cross-origin posture (topOrigin / crossOrigin).
    if client_data.origin != preimage.expected_origin {
        return Err(VerificationError::PreimageContextMismatch { field: "origin" });
    }
    origin_policy
        .evaluate(&OriginContext {
            rp_id: input.rp_id,
            origin: &client_data.origin,
            top_origin: client_data.top_origin.as_deref(),
            cross_origin: client_data.cross_origin,
        })
        .map_err(|reason| VerificationError::OriginRejected { reason })?;

    // 5-7. Parse authenticatorData header and validate rpIdHash + flags.
    if input.authenticator_data.len() < 37 {
        return Err(VerificationError::AuthenticatorDataTooShort);
    }
    let rp_id_hash = &input.authenticator_data[0..32];
    let flag_byte = input.authenticator_data[32];
    let asserted_sign_count = u32::from_be_bytes([
        input.authenticator_data[33],
        input.authenticator_data[34],
        input.authenticator_data[35],
        input.authenticator_data[36],
    ]);

    let expected_rp_hash: [u8; 32] = Sha256::digest(input.rp_id.as_bytes()).into();
    if !ct_eq(rp_id_hash, &expected_rp_hash) {
        return Err(VerificationError::RpIdHashMismatch);
    }

    // 6. UP and UV. UV is REQUIRED (not just UP). A set UV with clear UP is
    //    malformed and rejected.
    if flag_byte & flags::UP == 0 {
        return Err(VerificationError::UserPresenceMissing);
    }
    if flag_byte & flags::UV == 0 {
        return Err(VerificationError::UserVerificationMissing);
    }

    // 7. BE/BS policy: BS set while BE clear is spec-invalid; and a credential
    //    registered as backup-ineligible must not later assert BE.
    let be = flag_byte & flags::BE != 0;
    let bs = flag_byte & flags::BS != 0;
    if bs && !be {
        return Err(VerificationError::BackupFlagPolicy {
            reason: "backup-state set without backup-eligible".to_string(),
        });
    }
    if be && !credential.backup_eligible {
        return Err(VerificationError::BackupFlagPolicy {
            reason: "credential asserted backup-eligible but was registered ineligible".to_string(),
        });
    }

    // 8. signCount regression handling.
    sign_count_policy
        .evaluate(credential.sign_count, asserted_sign_count)
        .map_err(|reason| VerificationError::SignCountPolicy { reason })?;

    // 9. Signature over authenticatorData ∥ SHA-256(clientDataJSON).
    let client_data_hash: [u8; 32] = Sha256::digest(input.client_data_json).into();
    let mut verification_data =
        Vec::with_capacity(input.authenticator_data.len() + client_data_hash.len());
    verification_data.extend_from_slice(input.authenticator_data);
    verification_data.extend_from_slice(&client_data_hash);

    let ok = credential
        .public_key
        .verify(input.signature, &verification_data)
        .map_err(|e| VerificationError::VerificationInternal {
            reason: e.to_string(),
        })?;
    if !ok {
        return Err(VerificationError::BadSignature);
    }

    Ok(VerifiedAssertion {
        user: credential.user,
        credential_id: credential.credential_id,
        new_sign_count: asserted_sign_count,
        backup_state: bs,
        // Carry the bound gate/tx out of the verifier as proof of exactly which
        // gate + transaction THIS assertion authorized.
        gate_ref: preimage.gate_ref.clone(),
        rendered_tx_digest: preimage.rendered_tx_digest,
    })
}

/// Test-only software authenticator that mints ES256 (P-256) and EdDSA
/// (Ed25519) assertions, used to drive the verifier through valid + adversarial
/// paths.
#[cfg(test)]
pub(crate) mod test_authenticator {
    use super::*;
    use crate::webauthn::cose::CosePublicKey;

    /// A software authenticator over one of the supported algorithms.
    pub(crate) enum SoftwareAuthenticator {
        /// ES256 / P-256.
        Es256(p256::ecdsa::SigningKey),
        /// EdDSA / Ed25519.
        Ed25519(Box<ed25519_dalek::SigningKey>),
    }

    impl SoftwareAuthenticator {
        /// Generate a fresh P-256 (ES256) authenticator.
        pub(crate) fn new_p256() -> Self {
            SoftwareAuthenticator::Es256(p256::ecdsa::SigningKey::random(&mut rand_core::OsRng))
        }

        /// Generate a fresh Ed25519 (EdDSA) authenticator.
        pub(crate) fn new_ed25519() -> Self {
            SoftwareAuthenticator::Ed25519(Box::new(ed25519_dalek::SigningKey::generate(
                &mut rand_core::OsRng,
            )))
        }

        /// The COSE public key to register (in our pure-Rust representation).
        pub(crate) fn cose_key(&self) -> CosePublicKey {
            match self {
                SoftwareAuthenticator::Es256(sk) => {
                    let vk = sk.verifying_key();
                    let sec1 = vk.to_encoded_point(false).as_bytes().to_vec();
                    CosePublicKey::Es256 { sec1 }
                }
                SoftwareAuthenticator::Ed25519(sk) => CosePublicKey::Ed25519 {
                    public: sk.verifying_key().to_bytes(),
                },
            }
        }

        /// Build `authenticatorData` for the given rp_id + flags + sign count.
        pub(crate) fn authenticator_data(rp_id: &str, flag_byte: u8, sign_count: u32) -> Vec<u8> {
            let mut data = Vec::with_capacity(37);
            let rp_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
            data.extend_from_slice(&rp_hash);
            data.push(flag_byte);
            data.extend_from_slice(&sign_count.to_be_bytes());
            data
        }

        /// Build a `clientDataJSON` echoing `challenge` for the given origin
        /// (same-origin: `crossOrigin:false`, no `topOrigin`).
        pub(crate) fn client_data_json(
            type_: &str,
            challenge: &ChallengeCommitment,
            origin: &str,
        ) -> Vec<u8> {
            let chal_b64 = b64url_encode(challenge.as_bytes());
            format!(
                r#"{{"type":"{type_}","challenge":"{chal_b64}","origin":"{origin}","crossOrigin":false}}"#
            )
            .into_bytes()
        }

        /// Build a `clientDataJSON` with an explicit `crossOrigin` flag and an
        /// optional `topOrigin`, for cross-origin policy tests.
        pub(crate) fn client_data_json_cross(
            type_: &str,
            challenge: &ChallengeCommitment,
            origin: &str,
            cross_origin: bool,
            top_origin: Option<&str>,
        ) -> Vec<u8> {
            let chal_b64 = b64url_encode(challenge.as_bytes());
            let top = match top_origin {
                Some(t) => format!(r#","topOrigin":"{t}""#),
                None => String::new(),
            };
            format!(
                r#"{{"type":"{type_}","challenge":"{chal_b64}","origin":"{origin}","crossOrigin":{cross_origin}{top}}}"#
            )
            .into_bytes()
        }

        /// Build a `clientDataJSON` with NO `crossOrigin` key at all (it is
        /// OPTIONAL; absent must be treated as `false`).
        pub(crate) fn client_data_json_no_cross_key(
            type_: &str,
            challenge: &ChallengeCommitment,
            origin: &str,
        ) -> Vec<u8> {
            let chal_b64 = b64url_encode(challenge.as_bytes());
            format!(r#"{{"type":"{type_}","challenge":"{chal_b64}","origin":"{origin}"}}"#)
                .into_bytes()
        }

        /// Sign `authenticatorData ∥ SHA-256(clientDataJSON)`. ES256 returns a
        /// DER ECDSA signature; EdDSA returns the raw 64-byte signature — each
        /// matching what a real authenticator of that type emits.
        pub(crate) fn sign(&self, authenticator_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
            let client_data_hash: [u8; 32] = Sha256::digest(client_data_json).into();
            let mut msg = Vec::new();
            msg.extend_from_slice(authenticator_data);
            msg.extend_from_slice(&client_data_hash);
            match self {
                SoftwareAuthenticator::Es256(sk) => {
                    use p256::ecdsa::signature::Signer;
                    let sig: p256::ecdsa::Signature = sk.sign(&msg);
                    sig.to_der().as_bytes().to_vec()
                }
                SoftwareAuthenticator::Ed25519(sk) => {
                    use ed25519_dalek::Signer;
                    sk.sign(&msg).to_bytes().to_vec()
                }
            }
        }
    }

    /// base64url no-pad encode (test helper).
    fn b64url_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        let mut acc: u32 = 0;
        let mut nbits = 0u32;
        for &b in bytes {
            acc = (acc << 8) | b as u32;
            nbits += 8;
            while nbits >= 6 {
                nbits -= 6;
                out.push(ALPHABET[((acc >> nbits) & 0x3f) as usize] as char);
            }
        }
        if nbits > 0 {
            out.push(ALPHABET[((acc << (6 - nbits)) & 0x3f) as usize] as char);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::test_authenticator::SoftwareAuthenticator;
    use super::*;
    use crate::challenge::{ChallengePreimage, CredentialId, DeliveryAttemptId};
    use crate::webauthn::registry::{
        AttestationPolicy, BackupFlagPolicy, BootstrapPolicy, InMemoryWebAuthnCredentialRegistry,
        RegistrationRequest, StandardOriginPolicy,
    };
    use ironclaw_signing_provider::{
        ActorId, ApprovedTxHash, ChainId, GateRef, KeyOrAccountId, RunId, ScopeId, TenantId, UserId,
    };

    const RP_ID: &str = "ironclaw.example";
    const ORIGIN: &str = "https://ironclaw.example";
    const USER_HANDLE: &[u8] = b"alice-handle";

    struct AllowAll;
    impl AttestationPolicy for AllowAll {
        fn evaluate(&self, _r: &RegistrationRequest) -> Result<(), String> {
            Ok(())
        }
    }
    impl BackupFlagPolicy for AllowAll {
        fn evaluate(&self, _r: &RegistrationRequest) -> Result<(), String> {
            Ok(())
        }
    }
    impl BootstrapPolicy for AllowAll {
        fn evaluate(&self, _r: &RegistrationRequest, _n: usize) -> Result<(), String> {
            Ok(())
        }
    }

    /// Origin policy that only accepts the exact expected origin and rejects
    /// cross-origin assertions (the safe default posture).
    struct ExactOrigin;
    impl OriginPolicy for ExactOrigin {
        fn evaluate(&self, ctx: &OriginContext<'_>) -> Result<(), String> {
            if ctx.origin != ORIGIN {
                return Err(format!("disallowed origin {}", ctx.origin));
            }
            if ctx.cross_origin {
                return Err("cross-origin not permitted".to_string());
            }
            Ok(())
        }
    }

    /// Strict sign-count policy: asserted must be strictly greater than stored
    /// (rejects regression AND equal counts).
    struct StrictlyIncreasing;
    impl SignCountPolicy for StrictlyIncreasing {
        fn evaluate(&self, stored: u32, asserted: u32) -> Result<(), String> {
            if asserted > stored {
                Ok(())
            } else {
                Err(format!("non-increasing sign count {asserted} <= {stored}"))
            }
        }
    }

    fn preimage(commit_seed: u8) -> ChallengePreimage {
        ChallengePreimage {
            rp_id: RP_ID.to_string(),
            expected_origin: ORIGIN.to_string(),
            tenant: TenantId::new("tenant-a"),
            user: UserId::new("alice"),
            scope: ScopeId::new("scope-x"),
            actor: ActorId::new("actor-7"),
            credential_id: CredentialId::new(b"cred-1".to_vec()),
            run_id: RunId::new("run-42"),
            gate_ref: GateRef::new("gate:abc"),
            key_or_account_id: KeyOrAccountId::new("0xabc"),
            chain_id: ChainId::new("eip155:1"),
            expiry_ms: 10_000,
            delivery_attempt: DeliveryAttemptId::new("attempt-1"),
            rendered_tx_digest: ApprovedTxHash::from_bytes([commit_seed; 32]),
        }
    }

    fn consumed(preimage: ChallengePreimage) -> ConsumedChallenge {
        ConsumedChallenge {
            id: crate::challenge::ChallengeId::new("c1"),
            preimage,
        }
    }

    struct Fixture {
        registry: InMemoryWebAuthnCredentialRegistry,
        auth: SoftwareAuthenticator,
    }

    fn fixture(initial_sign_count: u32, backup_eligible: bool) -> Fixture {
        fixture_with(
            SoftwareAuthenticator::new_p256(),
            initial_sign_count,
            backup_eligible,
        )
    }

    fn fixture_with(
        auth: SoftwareAuthenticator,
        initial_sign_count: u32,
        backup_eligible: bool,
    ) -> Fixture {
        let registry = InMemoryWebAuthnCredentialRegistry::new(
            Box::new(AllowAll),
            Box::new(AllowAll),
            Box::new(AllowAll),
        );
        registry
            .register(RegistrationRequest {
                user: UserId::new("alice"),
                credential_id: CredentialId::new(b"cred-1".to_vec()),
                public_key: auth.cose_key(),
                aaguid: [0u8; 16],
                initial_sign_count,
                backup_eligible,
                backup_state: false,
            })
            .expect("register");
        Fixture { registry, auth }
    }

    /// Default valid flags: UP + UV set.
    const UP_UV: u8 = flags::UP | flags::UV;

    #[allow(clippy::too_many_arguments)]
    fn run(
        fx: &Fixture,
        pre: &ChallengePreimage,
        flag_byte: u8,
        asserted_count: u32,
        client_type: &str,
        origin: &str,
        challenge_commit: &ChallengeCommitment,
        user_handle: Option<&[u8]>,
        tamper_sig: bool,
    ) -> Result<VerifiedAssertion, VerificationError> {
        let ad = SoftwareAuthenticator::authenticator_data(RP_ID, flag_byte, asserted_count);
        let cdj = SoftwareAuthenticator::client_data_json(client_type, challenge_commit, origin);
        let mut sig = fx.auth.sign(&ad, &cdj);
        if tamper_sig {
            // Flip a byte in the DER signature body.
            let last = sig.len() - 1;
            sig[last] ^= 0xff;
        }
        let cons = consumed(pre.clone());
        let input = AssertionInput {
            expected_user: &UserId::new("alice"),
            user_handle,
            credential_id: &CredentialId::new(b"cred-1".to_vec()),
            authenticator_data: &ad,
            client_data_json: &cdj,
            signature: &sig,
            rp_id: RP_ID,
            consumed_challenge: &cons,
            expected_user_handle: USER_HANDLE,
        };
        verify_assertion(&fx.registry, &ExactOrigin, &StrictlyIncreasing, &input)
    }

    #[test]
    fn valid_assertion_with_uv_accepted() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let out = run(
            &fx,
            &pre,
            UP_UV,
            1,
            "webauthn.get",
            ORIGIN,
            &commit,
            None,
            false,
        )
        .expect("valid assertion must verify");
        assert_eq!(out.user, UserId::new("alice"));
        assert_eq!(out.new_sign_count, 1);
    }

    #[test]
    fn valid_ed25519_assertion_with_uv_accepted() {
        // Same full RP path, but the authenticator is EdDSA/Ed25519 — exercises
        // the pure-Rust ed25519-dalek verification leaf.
        let fx = fixture_with(SoftwareAuthenticator::new_ed25519(), 0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let out = run(
            &fx,
            &pre,
            UP_UV,
            1,
            "webauthn.get",
            ORIGIN,
            &commit,
            None,
            false,
        )
        .expect("valid Ed25519 assertion must verify");
        assert_eq!(out.user, UserId::new("alice"));
        assert_eq!(out.new_sign_count, 1);
    }

    #[test]
    fn bad_ed25519_signature_rejected() {
        let fx = fixture_with(SoftwareAuthenticator::new_ed25519(), 0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let res = run(
            &fx,
            &pre,
            UP_UV,
            1,
            "webauthn.get",
            ORIGIN,
            &commit,
            None,
            true,
        );
        assert!(matches!(
            res,
            Err(VerificationError::BadSignature)
                | Err(VerificationError::VerificationInternal { .. })
        ));
    }

    #[test]
    fn up_only_uv_clear_rejected() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let res = run(
            &fx,
            &pre,
            flags::UP,
            1,
            "webauthn.get",
            ORIGIN,
            &commit,
            None,
            false,
        );
        assert_eq!(res, Err(VerificationError::UserVerificationMissing));
    }

    #[test]
    fn up_clear_rejected() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        // UV set but UP clear is malformed.
        let res = run(
            &fx,
            &pre,
            flags::UV,
            1,
            "webauthn.get",
            ORIGIN,
            &commit,
            None,
            false,
        );
        assert_eq!(res, Err(VerificationError::UserPresenceMissing));
    }

    #[test]
    fn wrong_client_data_type_rejected() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let res = run(
            &fx,
            &pre,
            UP_UV,
            1,
            "webauthn.create",
            ORIGIN,
            &commit,
            None,
            false,
        );
        assert_eq!(res, Err(VerificationError::WrongClientDataType));
    }

    #[test]
    fn challenge_mismatch_rejected() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        // Echo a DIFFERENT challenge commitment than the one bound in `pre`.
        let other = preimage(99).commitment();
        let res = run(
            &fx,
            &pre,
            UP_UV,
            1,
            "webauthn.get",
            ORIGIN,
            &other,
            None,
            false,
        );
        assert_eq!(res, Err(VerificationError::ChallengeMismatch));
    }

    #[test]
    fn wrong_rp_id_hash_rejected() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        // Build authenticatorData for a DIFFERENT rp_id, but verify against RP_ID.
        let ad = SoftwareAuthenticator::authenticator_data("evil.example", UP_UV, 1);
        let cdj = SoftwareAuthenticator::client_data_json("webauthn.get", &commit, ORIGIN);
        let sig = fx.auth.sign(&ad, &cdj);
        let cons = consumed(pre.clone());
        let input = AssertionInput {
            expected_user: &UserId::new("alice"),
            user_handle: None,
            credential_id: &CredentialId::new(b"cred-1".to_vec()),
            authenticator_data: &ad,
            client_data_json: &cdj,
            signature: &sig,
            rp_id: RP_ID,
            consumed_challenge: &cons,
            expected_user_handle: USER_HANDLE,
        };
        assert_eq!(
            verify_assertion(&fx.registry, &ExactOrigin, &StrictlyIncreasing, &input),
            Err(VerificationError::RpIdHashMismatch)
        );
    }

    #[test]
    fn disallowed_origin_rejected_as_preimage_mismatch() {
        // The asserted origin differs from the origin bound in the preimage:
        // this now fails closed as a preimage-context mismatch (before the
        // injectable policy even runs).
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let res = run(
            &fx,
            &pre,
            UP_UV,
            1,
            "webauthn.get",
            "https://evil.example",
            &commit,
            None,
            false,
        );
        assert_eq!(
            res,
            Err(VerificationError::PreimageContextMismatch { field: "origin" })
        );
    }

    #[test]
    fn origin_policy_rejection_surfaces_as_origin_rejected() {
        // Origin matches the preimage, but an injectable policy that rejects the
        // posture (here: a cross-origin assertion under the same-origin-only
        // ExactOrigin) surfaces as OriginRejected — the policy path is live.
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let ad = SoftwareAuthenticator::authenticator_data(RP_ID, UP_UV, 1);
        let cdj = SoftwareAuthenticator::client_data_json_cross(
            "webauthn.get",
            &commit,
            ORIGIN,
            true,
            Some(ORIGIN),
        );
        let sig = fx.auth.sign(&ad, &cdj);
        let cons = consumed(pre.clone());
        let input = AssertionInput {
            expected_user: &UserId::new("alice"),
            user_handle: None,
            credential_id: &CredentialId::new(b"cred-1".to_vec()),
            authenticator_data: &ad,
            client_data_json: &cdj,
            signature: &sig,
            rp_id: RP_ID,
            consumed_challenge: &cons,
            expected_user_handle: USER_HANDLE,
        };
        assert!(matches!(
            verify_assertion(&fx.registry, &ExactOrigin, &StrictlyIncreasing, &input),
            Err(VerificationError::OriginRejected { .. })
        ));
    }

    /// Drive the verifier with a fully custom clientDataJSON (for crossOrigin /
    /// preimage-context tests), using `policy` as the origin policy.
    #[allow(clippy::too_many_arguments)]
    fn run_with(
        fx: &Fixture,
        pre: &ChallengePreimage,
        policy: &dyn OriginPolicy,
        expected_user: &UserId,
        credential_id: &CredentialId,
        rp_id: &str,
        cdj: &[u8],
    ) -> Result<VerifiedAssertion, VerificationError> {
        let ad = SoftwareAuthenticator::authenticator_data(RP_ID, UP_UV, 1);
        let sig = fx.auth.sign(&ad, cdj);
        let cons = consumed(pre.clone());
        let input = AssertionInput {
            expected_user,
            user_handle: None,
            credential_id,
            authenticator_data: &ad,
            client_data_json: cdj,
            signature: &sig,
            rp_id,
            consumed_challenge: &cons,
            expected_user_handle: USER_HANDLE,
        };
        verify_assertion(&fx.registry, policy, &StrictlyIncreasing, &input)
    }

    #[test]
    fn cross_origin_true_rejected_by_default() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let cdj = SoftwareAuthenticator::client_data_json_cross(
            "webauthn.get",
            &commit,
            ORIGIN,
            true,
            Some(ORIGIN),
        );
        let policy = StandardOriginPolicy::same_origin_only(ORIGIN);
        let res = run_with(
            &fx,
            &pre,
            &policy,
            &UserId::new("alice"),
            &CredentialId::new(b"cred-1".to_vec()),
            RP_ID,
            &cdj,
        );
        assert!(matches!(res, Err(VerificationError::OriginRejected { .. })));
    }

    #[test]
    fn cross_origin_true_missing_top_origin_rejected() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        // crossOrigin:true but NO topOrigin -> rejected even when cross-origin
        // is allowed.
        let cdj = SoftwareAuthenticator::client_data_json_cross(
            "webauthn.get",
            &commit,
            ORIGIN,
            true,
            None,
        );
        let policy = StandardOriginPolicy::allow_cross_origin_with_top(ORIGIN);
        let res = run_with(
            &fx,
            &pre,
            &policy,
            &UserId::new("alice"),
            &CredentialId::new(b"cred-1".to_vec()),
            RP_ID,
            &cdj,
        );
        assert!(matches!(res, Err(VerificationError::OriginRejected { .. })));
    }

    #[test]
    fn cross_origin_true_inconsistent_top_origin_rejected() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        // crossOrigin:true with a topOrigin that is NOT the expected origin.
        let cdj = SoftwareAuthenticator::client_data_json_cross(
            "webauthn.get",
            &commit,
            ORIGIN,
            true,
            Some("https://evil.example"),
        );
        let policy = StandardOriginPolicy::allow_cross_origin_with_top(ORIGIN);
        let res = run_with(
            &fx,
            &pre,
            &policy,
            &UserId::new("alice"),
            &CredentialId::new(b"cred-1".to_vec()),
            RP_ID,
            &cdj,
        );
        assert!(matches!(res, Err(VerificationError::OriginRejected { .. })));
    }

    #[test]
    fn cross_origin_true_with_matching_top_origin_accepted_when_allowed() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let cdj = SoftwareAuthenticator::client_data_json_cross(
            "webauthn.get",
            &commit,
            ORIGIN,
            true,
            Some(ORIGIN),
        );
        let policy = StandardOriginPolicy::allow_cross_origin_with_top(ORIGIN);
        let out = run_with(
            &fx,
            &pre,
            &policy,
            &UserId::new("alice"),
            &CredentialId::new(b"cred-1".to_vec()),
            RP_ID,
            &cdj,
        )
        .expect("cross-origin with matching topOrigin must verify when allowed");
        assert_eq!(out.user, UserId::new("alice"));
    }

    #[test]
    fn missing_cross_origin_key_treated_as_false() {
        // No crossOrigin key at all -> defaults to false -> accepted by the
        // same-origin-only policy.
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let cdj =
            SoftwareAuthenticator::client_data_json_no_cross_key("webauthn.get", &commit, ORIGIN);
        let policy = StandardOriginPolicy::same_origin_only(ORIGIN);
        let out = run_with(
            &fx,
            &pre,
            &policy,
            &UserId::new("alice"),
            &CredentialId::new(b"cred-1".to_vec()),
            RP_ID,
            &cdj,
        )
        .expect("absent crossOrigin must be treated as false and accepted");
        assert_eq!(out.new_sign_count, 1);
    }

    #[test]
    fn preimage_user_mismatch_fails_closed() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let cdj = SoftwareAuthenticator::client_data_json("webauthn.get", &commit, ORIGIN);
        // Caller claims a DIFFERENT user than the one bound in the preimage.
        let res = run_with(
            &fx,
            &pre,
            &ExactOrigin,
            &UserId::new("mallory"),
            &CredentialId::new(b"cred-1".to_vec()),
            RP_ID,
            &cdj,
        );
        assert_eq!(
            res,
            Err(VerificationError::PreimageContextMismatch { field: "user" })
        );
    }

    #[test]
    fn preimage_credential_mismatch_fails_closed() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let cdj = SoftwareAuthenticator::client_data_json("webauthn.get", &commit, ORIGIN);
        let res = run_with(
            &fx,
            &pre,
            &ExactOrigin,
            &UserId::new("alice"),
            &CredentialId::new(b"other-cred".to_vec()),
            RP_ID,
            &cdj,
        );
        assert_eq!(
            res,
            Err(VerificationError::PreimageContextMismatch {
                field: "credential_id"
            })
        );
    }

    #[test]
    fn preimage_rp_id_mismatch_fails_closed() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let cdj = SoftwareAuthenticator::client_data_json("webauthn.get", &commit, ORIGIN);
        let res = run_with(
            &fx,
            &pre,
            &ExactOrigin,
            &UserId::new("alice"),
            &CredentialId::new(b"cred-1".to_vec()),
            "other.rp",
            &cdj,
        );
        assert_eq!(
            res,
            Err(VerificationError::PreimageContextMismatch { field: "rp_id" })
        );
    }

    #[test]
    fn verified_assertion_carries_gate_and_tx_digest() {
        // The success output binds the gate_ref + rendered_tx_digest from the
        // consumed preimage (proof of THIS gate/tx).
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let out = run(
            &fx,
            &pre,
            UP_UV,
            1,
            "webauthn.get",
            ORIGIN,
            &commit,
            None,
            false,
        )
        .expect("valid assertion must verify");
        assert_eq!(out.gate_ref, pre.gate_ref);
        assert_eq!(out.rendered_tx_digest, pre.rendered_tx_digest);
    }

    #[test]
    fn non_canonical_challenge_trailing_bits_rejected() {
        // A base64url string whose final char carries non-zero trailing bits is
        // a non-canonical (malleable) encoding and must be rejected at decode.
        let fx = fixture(0, false);
        let pre = preimage(1);
        let ad = SoftwareAuthenticator::authenticator_data(RP_ID, UP_UV, 1);
        // 43 base64url chars decode to 32 bytes (the commitment length); the
        // last char ('B' = value 1) leaves 2 non-zero trailing bits.
        let bad_challenge = format!("{}B", "A".repeat(42));
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{bad_challenge}","origin":"{ORIGIN}","crossOrigin":false}}"#
        )
        .into_bytes();
        let sig = fx.auth.sign(&ad, &cdj);
        let cons = consumed(pre.clone());
        let input = AssertionInput {
            expected_user: &UserId::new("alice"),
            user_handle: None,
            credential_id: &CredentialId::new(b"cred-1".to_vec()),
            authenticator_data: &ad,
            client_data_json: &cdj,
            signature: &sig,
            rp_id: RP_ID,
            consumed_challenge: &cons,
            expected_user_handle: USER_HANDLE,
        };
        assert!(matches!(
            verify_assertion(&fx.registry, &ExactOrigin, &StrictlyIncreasing, &input),
            Err(VerificationError::MalformedClientData { .. })
        ));
    }

    #[test]
    fn sign_count_regression_rejected() {
        // Stored count 5; assert 3 -> regression.
        let fx = fixture(5, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let res = run(
            &fx,
            &pre,
            UP_UV,
            3,
            "webauthn.get",
            ORIGIN,
            &commit,
            None,
            false,
        );
        assert!(matches!(
            res,
            Err(VerificationError::SignCountPolicy { .. })
        ));
    }

    #[test]
    fn equal_sign_count_rejected_under_strict_policy() {
        // Stored 5, assert 5 -> rejected by the strictly-increasing policy.
        let fx = fixture(5, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let res = run(
            &fx,
            &pre,
            UP_UV,
            5,
            "webauthn.get",
            ORIGIN,
            &commit,
            None,
            false,
        );
        assert!(matches!(
            res,
            Err(VerificationError::SignCountPolicy { .. })
        ));
    }

    #[test]
    fn bad_signature_rejected() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let res = run(
            &fx,
            &pre,
            UP_UV,
            1,
            "webauthn.get",
            ORIGIN,
            &commit,
            None,
            true,
        );
        assert!(matches!(
            res,
            Err(VerificationError::BadSignature)
                | Err(VerificationError::VerificationInternal { .. })
        ));
    }

    #[test]
    fn unregistered_credential_rejected() {
        let fx = fixture(0, false);
        // Bind the challenge to an unregistered credential id so the assertion
        // context MATCHES the preimage (passing the context-binding step) but
        // the registry lookup misses -> UnknownCredential.
        let mut pre = preimage(1);
        pre.credential_id = CredentialId::new(b"not-registered".to_vec());
        let commit = pre.commitment();
        let ad = SoftwareAuthenticator::authenticator_data(RP_ID, UP_UV, 1);
        let cdj = SoftwareAuthenticator::client_data_json("webauthn.get", &commit, ORIGIN);
        let sig = fx.auth.sign(&ad, &cdj);
        let cons = consumed(pre.clone());
        let input = AssertionInput {
            expected_user: &UserId::new("alice"),
            user_handle: None,
            credential_id: &CredentialId::new(b"not-registered".to_vec()),
            authenticator_data: &ad,
            client_data_json: &cdj,
            signature: &sig,
            rp_id: RP_ID,
            consumed_challenge: &cons,
            expected_user_handle: USER_HANDLE,
        };
        assert_eq!(
            verify_assertion(&fx.registry, &ExactOrigin, &StrictlyIncreasing, &input),
            Err(VerificationError::UnknownCredential)
        );
    }

    #[test]
    fn foreign_user_handle_rejected() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let res = run(
            &fx,
            &pre,
            UP_UV,
            1,
            "webauthn.get",
            ORIGIN,
            &commit,
            Some(b"someone-else"),
            false,
        );
        assert_eq!(res, Err(VerificationError::ForeignUserHandle));
    }

    #[test]
    fn matching_user_handle_accepted() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let out = run(
            &fx,
            &pre,
            UP_UV,
            1,
            "webauthn.get",
            ORIGIN,
            &commit,
            Some(USER_HANDLE),
            false,
        )
        .expect("matching handle must verify");
        assert_eq!(out.user, UserId::new("alice"));
    }

    #[test]
    fn backup_state_without_eligible_rejected() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        // BS set, BE clear -> spec-invalid.
        let res = run(
            &fx,
            &pre,
            UP_UV | flags::BS,
            1,
            "webauthn.get",
            ORIGIN,
            &commit,
            None,
            false,
        );
        assert!(matches!(
            res,
            Err(VerificationError::BackupFlagPolicy { .. })
        ));
    }

    #[test]
    fn backup_eligible_assert_on_ineligible_registration_rejected() {
        // Registered as ineligible; assertion claims BE -> rejected.
        let fx = fixture(0, false);
        let pre = preimage(1);
        let commit = pre.commitment();
        let res = run(
            &fx,
            &pre,
            UP_UV | flags::BE,
            1,
            "webauthn.get",
            ORIGIN,
            &commit,
            None,
            false,
        );
        assert!(matches!(
            res,
            Err(VerificationError::BackupFlagPolicy { .. })
        ));
    }

    #[test]
    fn malformed_client_data_rejected() {
        let fx = fixture(0, false);
        let pre = preimage(1);
        let ad = SoftwareAuthenticator::authenticator_data(RP_ID, UP_UV, 1);
        let cdj = b"not json".to_vec();
        let sig = fx.auth.sign(&ad, &cdj);
        let cons = consumed(pre.clone());
        let input = AssertionInput {
            expected_user: &UserId::new("alice"),
            user_handle: None,
            credential_id: &CredentialId::new(b"cred-1".to_vec()),
            authenticator_data: &ad,
            client_data_json: &cdj,
            signature: &sig,
            rp_id: RP_ID,
            consumed_challenge: &cons,
            expected_user_handle: USER_HANDLE,
        };
        assert!(matches!(
            verify_assertion(&fx.registry, &ExactOrigin, &StrictlyIncreasing, &input),
            Err(VerificationError::MalformedClientData { .. })
        ));
    }
}
