//! WebAuthn credential registry.
//!
//! Stores the non-secret, integrity-relevant material captured at registration
//! time: credential id, COSE public key, AAGUID, current sign count, and the
//! backup-eligibility / backup-state (BE/BS) flags, bound to a specific user.
//!
//! ## Public keys are non-secret
//!
//! A WebAuthn credential public key is not secret, but it IS integrity-relevant
//! (a swapped key would let an attacker's authenticator pass verification).
//! The in-memory registry stores it plainly; integrity protection of the
//! durable record (a MAC / signed row) is a durable-backend concern and is out
//! of scope for this in-memory impl — noted for the stacked PG / libSQL
//! follow-up.
//!
//! ## Policy hooks
//!
//! Registration runs three injectable, fail-closed policy hooks:
//!
//! - [`AttestationPolicy`]: accept / reject by AAGUID + attestation posture
//!   (e.g. an allowlist of certified authenticator models).
//! - [`BackupFlagPolicy`]: accept / reject by BE/BS at registration (e.g.
//!   refuse backup-eligible passkeys for the highest-value custody tier).
//! - [`BootstrapPolicy`]: authorize the registration itself. **Open question:**
//!   what authorizes the very *first* credential registration before any
//!   attested channel exists (the bootstrap trust anchor)? We do not resolve
//!   the policy here; we make it an injected hook and ship a conservative
//!   default that DENIES bootstrap unless an explicit allow is configured, so
//!   the fail-closed posture holds until the anchor is decided. See the PR body
//!   open-questions section.

use std::collections::HashMap;
use std::sync::Mutex;

use thiserror::Error;

use ironclaw_signing_provider::UserId;

use crate::challenge::CredentialId;
use crate::webauthn::cose::CosePublicKey;

/// AAGUID — the 16-byte authenticator model identifier.
pub type Aaguid = [u8; 16];

/// A credential as captured at registration and stored for later assertion
/// verification.
#[derive(Clone, Debug)]
pub struct RegisteredCredential {
    /// User the credential belongs to. Assertions are bound to this user.
    pub user: UserId,
    /// Credential id (the `id` echoed in `allowCredentials` / the assertion).
    pub credential_id: CredentialId,
    /// COSE public key used to verify assertion signatures.
    pub public_key: CosePublicKey,
    /// Authenticator model identifier.
    pub aaguid: Aaguid,
    /// Current signature counter. Monotonic non-decreasing across assertions;
    /// a regression indicates a cloned authenticator.
    pub sign_count: u32,
    /// Backup-eligibility flag (BE) observed at registration.
    pub backup_eligible: bool,
    /// Backup-state flag (BS) observed at registration.
    pub backup_state: bool,
}

/// The inputs to a registration request, separated from the stored record so
/// the policy hooks see exactly what was presented.
#[derive(Clone, Debug)]
pub struct RegistrationRequest {
    /// User the credential will belong to.
    pub user: UserId,
    /// Credential id.
    pub credential_id: CredentialId,
    /// COSE public key.
    pub public_key: CosePublicKey,
    /// Authenticator model identifier.
    pub aaguid: Aaguid,
    /// Initial signature counter.
    pub initial_sign_count: u32,
    /// Backup-eligibility flag (BE) at registration.
    pub backup_eligible: bool,
    /// Backup-state flag (BS) at registration.
    pub backup_state: bool,
}

/// Errors registration can surface. All are fail-closed (the credential is NOT
/// registered).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistrationError {
    /// A credential with this id is already registered (ids are unique).
    #[error("credential id already registered")]
    DuplicateCredentialId,

    /// The [`AttestationPolicy`] rejected the AAGUID / attestation posture.
    #[error("attestation policy rejected the authenticator: {reason}")]
    AttestationRejected {
        /// Human-readable, non-secret rejection reason.
        reason: String,
    },

    /// The [`BackupFlagPolicy`] rejected the BE/BS posture.
    #[error("backup-flag policy rejected the credential: {reason}")]
    BackupFlagRejected {
        /// Human-readable, non-secret rejection reason.
        reason: String,
    },

    /// The [`BootstrapPolicy`] refused to authorize this registration.
    #[error("bootstrap policy denied registration: {reason}")]
    BootstrapDenied {
        /// Human-readable, non-secret denial reason.
        reason: String,
    },

    /// A backend-internal failure.
    #[error("registry error: {reason}")]
    Backend {
        /// Human-readable description of the backend failure.
        reason: String,
    },
}

/// Injectable attestation policy: decide whether an authenticator's AAGUID and
/// attestation posture are acceptable. Fail-closed: return `Err` to reject.
pub trait AttestationPolicy: Send + Sync {
    /// Evaluate the request. `Ok(())` accepts; `Err(reason)` rejects.
    fn evaluate(&self, request: &RegistrationRequest) -> Result<(), String>;
}

/// Injectable backup-flag policy: decide whether the BE/BS posture is
/// acceptable for the custody tier. Fail-closed.
pub trait BackupFlagPolicy: Send + Sync {
    /// Evaluate the request. `Ok(())` accepts; `Err(reason)` rejects.
    fn evaluate(&self, request: &RegistrationRequest) -> Result<(), String>;
}

/// Injectable bootstrap policy: authorize the registration operation itself.
///
/// `existing_credentials_for_user` is the count of credentials already
/// registered for the requesting user, so a policy can distinguish the
/// first-credential bootstrap case (count == 0) from a subsequent
/// add-a-passkey case (which can be authorized by an existing attested
/// credential). Fail-closed.
pub trait BootstrapPolicy: Send + Sync {
    /// Evaluate the request. `Ok(())` authorizes; `Err(reason)` denies.
    fn evaluate(
        &self,
        request: &RegistrationRequest,
        existing_credentials_for_user: usize,
    ) -> Result<(), String>;
}

/// Injectable origin policy used by the verifier (lives here so registry and
/// verifier share one policy vocabulary). Fail-closed: return `Err` to reject.
pub trait OriginPolicy: Send + Sync {
    /// Decide whether the presented `origin` (and optional `top_origin`) are
    /// acceptable for the given RP id.
    fn evaluate(&self, rp_id: &str, origin: &str, top_origin: Option<&str>) -> Result<(), String>;
}

/// Injectable sign-count policy: decide how to treat the relationship between
/// the stored count and the asserted count. Fail-closed for regressions.
pub trait SignCountPolicy: Send + Sync {
    /// `stored` is the last-seen count, `asserted` is from the new assertion.
    /// `Ok(())` accepts; `Err(reason)` rejects (e.g. regression =
    /// cloned-authenticator).
    fn evaluate(&self, stored: u32, asserted: u32) -> Result<(), String>;
}

/// WebAuthn credential registry.
///
/// `register` enforces uniqueness of credential ids and runs the three
/// fail-closed policy hooks; `lookup` retrieves a credential by `(user,
/// credential_id)` — binding the lookup to the user prevents using one user's
/// credential under another user's identity.
pub trait WebAuthnCredentialRegistry: Send + Sync {
    /// Register a credential after policy checks. Fails closed on any policy
    /// rejection or a duplicate id.
    fn register(&self, request: RegistrationRequest) -> Result<(), RegistrationError>;

    /// Look up a registered credential by user + credential id. Returns `None`
    /// if no such credential is registered for that user.
    fn lookup(&self, user: &UserId, credential_id: &CredentialId) -> Option<RegisteredCredential>;

    /// Persist an updated sign count for a credential (called by the call site
    /// after a successful assertion). Fails closed if the credential is gone.
    fn update_sign_count(
        &self,
        user: &UserId,
        credential_id: &CredentialId,
        new_count: u32,
    ) -> Result<(), RegistrationError>;
}

/// In-memory [`WebAuthnCredentialRegistry`].
///
/// Credential ids are globally unique keys (a credential id is unique per
/// authenticator by spec); the stored record carries the bound user so
/// `lookup` can enforce user ownership.
pub struct InMemoryWebAuthnCredentialRegistry {
    credentials: Mutex<HashMap<CredentialId, RegisteredCredential>>,
    attestation_policy: Box<dyn AttestationPolicy>,
    backup_policy: Box<dyn BackupFlagPolicy>,
    bootstrap_policy: Box<dyn BootstrapPolicy>,
}

impl std::fmt::Debug for InMemoryWebAuthnCredentialRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryWebAuthnCredentialRegistry")
            .field("credentials", &"<locked>")
            .finish_non_exhaustive()
    }
}

impl InMemoryWebAuthnCredentialRegistry {
    /// Construct a registry with explicit policy hooks.
    pub fn new(
        attestation_policy: Box<dyn AttestationPolicy>,
        backup_policy: Box<dyn BackupFlagPolicy>,
        bootstrap_policy: Box<dyn BootstrapPolicy>,
    ) -> Self {
        Self {
            credentials: Mutex::new(HashMap::new()),
            attestation_policy,
            backup_policy,
            bootstrap_policy,
        }
    }

    fn count_for_user(map: &HashMap<CredentialId, RegisteredCredential>, user: &UserId) -> usize {
        map.values().filter(|c| &c.user == user).count()
    }
}

impl WebAuthnCredentialRegistry for InMemoryWebAuthnCredentialRegistry {
    fn register(&self, request: RegistrationRequest) -> Result<(), RegistrationError> {
        let mut map = self
            .credentials
            .lock()
            .map_err(|e| RegistrationError::Backend {
                reason: e.to_string(),
            })?;

        if map.contains_key(&request.credential_id) {
            return Err(RegistrationError::DuplicateCredentialId);
        }

        // Bootstrap authorization runs FIRST: a registration that is not
        // authorized at all must never reach attestation/backup evaluation.
        let existing = Self::count_for_user(&map, &request.user);
        self.bootstrap_policy
            .evaluate(&request, existing)
            .map_err(|reason| RegistrationError::BootstrapDenied { reason })?;

        self.attestation_policy
            .evaluate(&request)
            .map_err(|reason| RegistrationError::AttestationRejected { reason })?;

        self.backup_policy
            .evaluate(&request)
            .map_err(|reason| RegistrationError::BackupFlagRejected { reason })?;

        map.insert(
            request.credential_id.clone(),
            RegisteredCredential {
                user: request.user,
                credential_id: request.credential_id,
                public_key: request.public_key,
                aaguid: request.aaguid,
                sign_count: request.initial_sign_count,
                backup_eligible: request.backup_eligible,
                backup_state: request.backup_state,
            },
        );
        Ok(())
    }

    fn lookup(&self, user: &UserId, credential_id: &CredentialId) -> Option<RegisteredCredential> {
        let map = self.credentials.lock().ok()?;
        map.get(credential_id).filter(|c| &c.user == user).cloned()
    }

    fn update_sign_count(
        &self,
        user: &UserId,
        credential_id: &CredentialId,
        new_count: u32,
    ) -> Result<(), RegistrationError> {
        let mut map = self
            .credentials
            .lock()
            .map_err(|e| RegistrationError::Backend {
                reason: e.to_string(),
            })?;
        match map.get_mut(credential_id) {
            Some(cred) if &cred.user == user => {
                cred.sign_count = new_count;
                Ok(())
            }
            _ => Err(RegistrationError::Backend {
                reason: "credential not found for user".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::verify::test_authenticator::SoftwareAuthenticator;

    /// Allow-all attestation policy for tests.
    struct AllowAttestation;
    impl AttestationPolicy for AllowAttestation {
        fn evaluate(&self, _r: &RegistrationRequest) -> Result<(), String> {
            Ok(())
        }
    }
    struct AllowBackup;
    impl BackupFlagPolicy for AllowBackup {
        fn evaluate(&self, _r: &RegistrationRequest) -> Result<(), String> {
            Ok(())
        }
    }
    struct AllowBootstrap;
    impl BootstrapPolicy for AllowBootstrap {
        fn evaluate(&self, _r: &RegistrationRequest, _n: usize) -> Result<(), String> {
            Ok(())
        }
    }

    fn permissive_registry() -> InMemoryWebAuthnCredentialRegistry {
        InMemoryWebAuthnCredentialRegistry::new(
            Box::new(AllowAttestation),
            Box::new(AllowBackup),
            Box::new(AllowBootstrap),
        )
    }

    fn request_for(user: &str, cred_id: &[u8]) -> RegistrationRequest {
        let auth = SoftwareAuthenticator::new_p256();
        RegistrationRequest {
            user: UserId::new(user),
            credential_id: CredentialId::new(cred_id.to_vec()),
            public_key: auth.cose_key(),
            aaguid: [0u8; 16],
            initial_sign_count: 0,
            backup_eligible: false,
            backup_state: false,
        }
    }

    #[test]
    fn register_then_lookup_round_trips() {
        let reg = permissive_registry();
        let req = request_for("alice", b"cred-1");
        reg.register(req).expect("register");
        let found = reg
            .lookup(
                &UserId::new("alice"),
                &CredentialId::new(b"cred-1".to_vec()),
            )
            .expect("lookup");
        assert_eq!(found.user, UserId::new("alice"));
    }

    #[test]
    fn duplicate_credential_id_rejected() {
        let reg = permissive_registry();
        reg.register(request_for("alice", b"dup")).expect("first");
        assert_eq!(
            reg.register(request_for("alice", b"dup")),
            Err(RegistrationError::DuplicateCredentialId)
        );
    }

    #[test]
    fn lookup_under_wrong_user_returns_none() {
        let reg = permissive_registry();
        reg.register(request_for("alice", b"cred-x")).expect("reg");
        assert!(
            reg.lookup(
                &UserId::new("mallory"),
                &CredentialId::new(b"cred-x".to_vec())
            )
            .is_none(),
            "a credential must not be visible under a different user"
        );
    }

    #[test]
    fn attestation_policy_rejection_fails_closed() {
        struct DenyAttestation;
        impl AttestationPolicy for DenyAttestation {
            fn evaluate(&self, _r: &RegistrationRequest) -> Result<(), String> {
                Err("aaguid not on allowlist".to_string())
            }
        }
        let reg = InMemoryWebAuthnCredentialRegistry::new(
            Box::new(DenyAttestation),
            Box::new(AllowBackup),
            Box::new(AllowBootstrap),
        );
        assert!(matches!(
            reg.register(request_for("alice", b"c")),
            Err(RegistrationError::AttestationRejected { .. })
        ));
        assert!(
            reg.lookup(&UserId::new("alice"), &CredentialId::new(b"c".to_vec()))
                .is_none()
        );
    }

    #[test]
    fn backup_policy_rejection_fails_closed() {
        struct DenyBackup;
        impl BackupFlagPolicy for DenyBackup {
            fn evaluate(&self, _r: &RegistrationRequest) -> Result<(), String> {
                Err("backup-eligible not allowed at this tier".to_string())
            }
        }
        let reg = InMemoryWebAuthnCredentialRegistry::new(
            Box::new(AllowAttestation),
            Box::new(DenyBackup),
            Box::new(AllowBootstrap),
        );
        assert!(matches!(
            reg.register(request_for("alice", b"c")),
            Err(RegistrationError::BackupFlagRejected { .. })
        ));
    }

    #[test]
    fn bootstrap_policy_denies_first_credential_by_default_posture() {
        // Conservative default: deny the first credential (count == 0) and only
        // allow a subsequent add. This models the fail-closed open-question
        // stance — the real anchor is TBD.
        struct DenyFirst;
        impl BootstrapPolicy for DenyFirst {
            fn evaluate(&self, _r: &RegistrationRequest, existing: usize) -> Result<(), String> {
                if existing == 0 {
                    Err("no bootstrap trust anchor for first credential".to_string())
                } else {
                    Ok(())
                }
            }
        }
        let reg = InMemoryWebAuthnCredentialRegistry::new(
            Box::new(AllowAttestation),
            Box::new(AllowBackup),
            Box::new(DenyFirst),
        );
        assert!(matches!(
            reg.register(request_for("alice", b"first")),
            Err(RegistrationError::BootstrapDenied { .. })
        ));
    }
}
