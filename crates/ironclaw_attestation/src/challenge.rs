//! Durable one-shot WebAuthn challenge store.
//!
//! The challenge is the anti-replay nonce of the custodial attested-signing
//! path. It is *bound* to the exact operation being authorized via a
//! [`ChallengePreimage`] that folds in every identity / scope / target field
//! plus the binding [`ApprovedTxHash`] (PR2). The value actually handed to the
//! client is a [`ChallengeCommitment`] — a domain-separated SHA-256 over the
//! preimage. The WebAuthn authenticator signs over `clientDataJSON` whose
//! `challenge` echoes this commitment; the verifier (see [`crate::webauthn`])
//! checks the echo equals what we issued.
//!
//! ## One-shot + expiry contract
//!
//! [`ChallengeStore::consume`] is an **atomic one-shot**: the first consume of
//! an issued, unexpired challenge wins and atomically marks it consumed; every
//! later consume of that id fails with [`ChallengeError::AlreadyConsumed`].
//! Expired challenges fail with [`ChallengeError::Expired`]; unknown ids with
//! [`ChallengeError::NotFound`]. This is the same rigor as the PR3 grant
//! `claim`: the seal/expiry check and the mark-consumed happen in a single
//! critical section, so under contention exactly one consumer wins.
//!
//! The plan intends this consume to be atomic with the credential signCount
//! update + gate resolution at the call site (PR5). This PR provides only the
//! one-shot store primitive; durable PG / libSQL backends are stacked
//! follow-ups gated by the [`challenge_store_contract_cases!`] macro and are
//! NOT implemented here.
//!
//! ## Encoding
//!
//! [`ChallengePreimage::encode`] reuses the PR2 hand-rolled, domain-separated,
//! length-prefixed encoding (no CBOR dependency). Length-prefixing every bound
//! field makes the encoding injective: changing ANY field changes the bytes
//! and therefore the commitment, so a challenge issued for one operation can
//! never be replayed to authorize a different one.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use ironclaw_signing_provider::{
    ActorId, ApprovedTxHash, ChainId, GateRef, KeyOrAccountId, RunId, ScopeId, TenantId, UserId,
};

/// Domain separator for the challenge preimage. Distinct from the canonical and
/// approved-tx-hash domains so the three pre-images can never be confused.
const CHALLENGE_DOMAIN: &[u8] = b"ironclaw.attestation.challenge.v1";

/// Opaque identifier of an issued challenge. Used as the consume key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChallengeId(String);

impl ChallengeId {
    /// Construct from any string-like value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Identifier of a registered WebAuthn credential, bound into the preimage so a
/// challenge is tied to the credential expected to answer it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialId(Vec<u8>);

impl CredentialId {
    /// Construct from raw credential-id bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Borrow the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Identifier of a single delivery attempt (the agent may re-prompt the user;
/// each prompt gets a fresh attempt id so an old prompt's challenge cannot be
/// reused for a new one).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeliveryAttemptId(String);

impl DeliveryAttemptId {
    /// Construct from any string-like value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Everything a challenge is bound to.
///
/// Constructing the preimage requires ALL of these fields — there is no
/// builder shortcut that omits one — so a caller cannot accidentally issue an
/// under-bound challenge. The [`ChallengePreimage::encode`] output is injective
/// over this field set (see module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengePreimage {
    /// WebAuthn Relying Party ID the assertion must be scoped to.
    pub rp_id: String,
    /// The exact origin the client is expected to present in `clientDataJSON`.
    pub expected_origin: String,
    /// Tenant boundary.
    pub tenant: TenantId,
    /// End user.
    pub user: UserId,
    /// Authorization scope.
    pub scope: ScopeId,
    /// Acting principal.
    pub actor: ActorId,
    /// Credential expected to answer this challenge.
    pub credential_id: CredentialId,
    /// Owning run.
    pub run_id: RunId,
    /// Gate the flow is blocked on.
    pub gate_ref: GateRef,
    /// Signing key or account.
    pub key_or_account_id: KeyOrAccountId,
    /// Target chain / network.
    pub chain_id: ChainId,
    /// Absolute expiry (unix millis). A consume at or after this instant fails
    /// [`ChallengeError::Expired`].
    pub expiry_ms: i64,
    /// Delivery attempt this challenge belongs to.
    pub delivery_attempt: DeliveryAttemptId,
    /// The binding hash of the approved transaction (PR2).
    pub rendered_tx_digest: ApprovedTxHash,
}

/// Append `len(bytes) ∥ bytes` to `out`.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

impl ChallengePreimage {
    /// Deterministic, domain-separated, length-prefixed encoding of every bound
    /// field, in fixed order. Identical input yields identical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CHALLENGE_DOMAIN);
        push_lp(&mut out, self.rp_id.as_bytes());
        push_lp(&mut out, self.expected_origin.as_bytes());
        push_lp(&mut out, self.tenant.as_str().as_bytes());
        push_lp(&mut out, self.user.as_str().as_bytes());
        push_lp(&mut out, self.scope.as_str().as_bytes());
        push_lp(&mut out, self.actor.as_str().as_bytes());
        push_lp(&mut out, self.credential_id.as_bytes());
        push_lp(&mut out, self.run_id.as_str().as_bytes());
        push_lp(&mut out, self.gate_ref.as_str().as_bytes());
        push_lp(&mut out, self.key_or_account_id.as_str().as_bytes());
        push_lp(&mut out, self.chain_id.as_str().as_bytes());
        out.extend_from_slice(&self.expiry_ms.to_be_bytes());
        push_lp(&mut out, self.delivery_attempt.as_str().as_bytes());
        push_lp(&mut out, self.rendered_tx_digest.as_bytes());
        out
    }

    /// Compute the [`ChallengeCommitment`] handed to the client: a
    /// domain-separated SHA-256 over [`ChallengePreimage::encode`].
    pub fn commitment(&self) -> ChallengeCommitment {
        let digest: [u8; 32] = Sha256::digest(self.encode()).into();
        ChallengeCommitment(digest)
    }
}

/// 32-byte commitment over a [`ChallengePreimage`] — the value sent to the
/// client and echoed back in `clientDataJSON.challenge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChallengeCommitment([u8; 32]);

impl ChallengeCommitment {
    /// Construct from raw bytes (e.g. when rehydrating from storage).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An issued, not-yet-consumed challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedChallenge {
    /// Opaque consume key.
    pub id: ChallengeId,
    /// The full preimage (carried so the verifier can recompute / inspect the
    /// bound fields; the commitment is derived from it).
    pub preimage: ChallengePreimage,
}

impl IssuedChallenge {
    /// The commitment value handed to the client for this challenge.
    pub fn commitment(&self) -> ChallengeCommitment {
        self.preimage.commitment()
    }
}

/// The result of a successful [`ChallengeStore::consume`].
///
/// Holding one of these is proof that *this* consumer won the one-shot race for
/// an unexpired challenge and is authorized to proceed to assertion
/// verification against the bound preimage exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumedChallenge {
    /// The challenge id that was consumed.
    pub id: ChallengeId,
    /// The bound preimage (the verifier checks the echoed challenge equals
    /// `preimage.commitment()` and the assertion against the bound fields).
    pub preimage: ChallengePreimage,
}

/// Errors a [`ChallengeStore`] can surface.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChallengeError {
    /// `issue` was called with an id that is already issued.
    #[error("challenge already issued for this id")]
    AlreadyIssued,

    /// `consume` was called for an id that was never issued.
    #[error("no challenge found for this id")]
    NotFound,

    /// `consume` lost the one-shot race: the challenge was already consumed.
    #[error("challenge already consumed (one-shot)")]
    AlreadyConsumed,

    /// `consume` was called at or after the challenge expiry.
    #[error("challenge expired")]
    Expired,

    /// A backend-internal failure with an opaque description.
    #[error("challenge store error: {reason}")]
    Backend {
        /// Human-readable description of the backend failure.
        reason: String,
    },
}

/// Durable one-shot challenge store.
///
/// `consume` MUST be an atomic, one-shot operation: the issued-check, the
/// expiry check, and the mark-consumed happen in a single critical section so
/// that under concurrent consumes of an unexpired challenge exactly one caller
/// observes it un-consumed and transitions it to consumed; all others fail.
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    /// Persist an issued challenge. Fails with
    /// [`ChallengeError::AlreadyIssued`] if a challenge with the same id is
    /// already issued (issuance is one-shot per id).
    async fn issue(&self, challenge: IssuedChallenge) -> Result<(), ChallengeError>;

    /// Atomically consume an issued, unexpired challenge exactly once.
    ///
    /// `now_ms` is the caller's notion of the current time (unix millis); a
    /// challenge whose `expiry_ms <= now_ms` fails [`ChallengeError::Expired`].
    /// The clock is injected rather than read internally so the one-shot /
    /// expiry semantics are deterministically testable and identical across
    /// backends.
    ///
    /// * First consume of an issued, unexpired id -> `Ok(ConsumedChallenge)`.
    /// * Any later consume of that id -> `Err(ChallengeError::AlreadyConsumed)`.
    /// * Consume of an expired id -> `Err(ChallengeError::Expired)`.
    /// * Consume of an unknown id -> `Err(ChallengeError::NotFound)`.
    async fn consume(
        &self,
        id: &ChallengeId,
        now_ms: i64,
    ) -> Result<ConsumedChallenge, ChallengeError>;
}

/// Internal stored state of a challenge.
#[derive(Debug, Clone)]
struct StoredChallenge {
    preimage: ChallengePreimage,
    consumed: bool,
}

/// In-memory [`ChallengeStore`].
///
/// The single [`Mutex`] guards the whole map, so the issued/expiry-check and
/// mark-consumed in [`ChallengeStore::consume`] is one critical section —
/// concurrent consumes serialize and exactly one wins.
#[derive(Debug, Default)]
pub struct InMemoryChallengeStore {
    challenges: Mutex<HashMap<ChallengeId, StoredChallenge>>,
}

impl InMemoryChallengeStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ChallengeStore for InMemoryChallengeStore {
    async fn issue(&self, challenge: IssuedChallenge) -> Result<(), ChallengeError> {
        let mut map = self
            .challenges
            .lock()
            .map_err(|e| ChallengeError::Backend {
                reason: e.to_string(),
            })?;
        if map.contains_key(&challenge.id) {
            return Err(ChallengeError::AlreadyIssued);
        }
        map.insert(
            challenge.id,
            StoredChallenge {
                preimage: challenge.preimage,
                consumed: false,
            },
        );
        Ok(())
    }

    async fn consume(
        &self,
        id: &ChallengeId,
        now_ms: i64,
    ) -> Result<ConsumedChallenge, ChallengeError> {
        let mut map = self
            .challenges
            .lock()
            .map_err(|e| ChallengeError::Backend {
                reason: e.to_string(),
            })?;
        // Issued-check, expiry-check, and mark-consumed in one critical section:
        // the lock is held across all three, so concurrent consumes cannot both
        // observe the challenge un-consumed. Expiry is checked BEFORE the
        // one-shot transition so an expired challenge is never "spent".
        let stored = map.get_mut(id).ok_or(ChallengeError::NotFound)?;
        if stored.consumed {
            return Err(ChallengeError::AlreadyConsumed);
        }
        if stored.preimage.expiry_ms <= now_ms {
            return Err(ChallengeError::Expired);
        }
        stored.consumed = true;
        Ok(ConsumedChallenge {
            id: id.clone(),
            preimage: stored.preimage.clone(),
        })
    }
}

/// Canonical contract suite for [`ChallengeStore`] implementations.
///
/// Mirrors `sealed_grant_store_contract_cases!` (PR3): the behavioural contract
/// lives once and every backend (in-memory here, durable PG / libSQL in stacked
/// follow-ups) is driven through it. Invoke with a label and a zero-arg factory
/// closure returning a fresh store.
#[cfg(test)]
pub(crate) mod contract {
    use super::*;
    use std::sync::Arc;

    pub(crate) fn preimage(seed: u8, expiry_ms: i64) -> ChallengePreimage {
        ChallengePreimage {
            rp_id: "ironclaw.example".to_string(),
            expected_origin: "https://ironclaw.example".to_string(),
            tenant: TenantId::new("tenant-a"),
            user: UserId::new("user-1"),
            scope: ScopeId::new("scope-x"),
            actor: ActorId::new("actor-7"),
            credential_id: CredentialId::new(vec![seed; 16]),
            run_id: RunId::new("run-42"),
            gate_ref: GateRef::new("gate:abc"),
            key_or_account_id: KeyOrAccountId::new("0xabc"),
            chain_id: ChainId::new("eip155:1"),
            expiry_ms,
            delivery_attempt: DeliveryAttemptId::new("attempt-1"),
            rendered_tx_digest: ApprovedTxHash::from_bytes([seed; 32]),
        }
    }

    pub(crate) fn issued(id: &str, seed: u8, expiry_ms: i64) -> IssuedChallenge {
        IssuedChallenge {
            id: ChallengeId::new(id),
            preimage: preimage(seed, expiry_ms),
        }
    }

    pub(crate) async fn issue_then_consume_succeeds<S: ChallengeStore>(store: S) {
        let ch = issued("c1", 1, 10_000);
        let commitment = ch.commitment();
        store.issue(ch).await.expect("issue must succeed");
        let consumed = store
            .consume(&ChallengeId::new("c1"), 5_000)
            .await
            .expect("first consume must succeed");
        assert_eq!(consumed.id, ChallengeId::new("c1"));
        // The consumed preimage still derives the same commitment we issued.
        assert_eq!(consumed.preimage.commitment(), commitment);
    }

    pub(crate) async fn second_consume_is_already_consumed<S: ChallengeStore>(store: S) {
        let ch = issued("c2", 2, 10_000);
        store.issue(ch).await.expect("issue");
        store
            .consume(&ChallengeId::new("c2"), 1)
            .await
            .expect("first consume");
        assert_eq!(
            store.consume(&ChallengeId::new("c2"), 2).await,
            Err(ChallengeError::AlreadyConsumed)
        );
    }

    pub(crate) async fn consume_unknown_is_not_found<S: ChallengeStore>(store: S) {
        assert_eq!(
            store.consume(&ChallengeId::new("nope"), 0).await,
            Err(ChallengeError::NotFound)
        );
    }

    pub(crate) async fn consume_expired_is_expired<S: ChallengeStore>(store: S) {
        let ch = issued("c3", 3, 1_000);
        store.issue(ch).await.expect("issue");
        // now == expiry -> expired (boundary is inclusive).
        assert_eq!(
            store.consume(&ChallengeId::new("c3"), 1_000).await,
            Err(ChallengeError::Expired)
        );
        // strictly after expiry -> still expired, and never marked consumed.
        assert_eq!(
            store.consume(&ChallengeId::new("c3"), 2_000).await,
            Err(ChallengeError::Expired)
        );
    }

    pub(crate) async fn double_issue_is_already_issued<S: ChallengeStore>(store: S) {
        store.issue(issued("c4", 4, 10_000)).await.expect("issue");
        assert_eq!(
            store.issue(issued("c4", 4, 10_000)).await,
            Err(ChallengeError::AlreadyIssued)
        );
    }

    pub(crate) async fn concurrent_consumes_yield_exactly_one_winner<S>(store: S)
    where
        S: ChallengeStore + 'static,
    {
        let store = Arc::new(store);
        store
            .issue(issued("c5", 5, 1_000_000))
            .await
            .expect("issue");

        let mut handles = Vec::new();
        for _ in 0..32 {
            let store = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                store.consume(&ChallengeId::new("c5"), 1).await
            }));
        }

        let mut ok = 0usize;
        let mut already = 0usize;
        for h in handles {
            match h.await.expect("task join") {
                Ok(_) => ok += 1,
                Err(ChallengeError::AlreadyConsumed) => already += 1,
                Err(other) => panic!("unexpected error under contention: {other:?}"),
            }
        }
        assert_eq!(ok, 1, "exactly one consume must win the one-shot race");
        assert_eq!(already, 31, "all other consumes must be AlreadyConsumed");
    }

    /// Drive every contract case against a fresh store from `$factory`.
    #[macro_export]
    macro_rules! challenge_store_contract_cases {
        ($label:ident, $factory:expr) => {
            mod $label {
                #[tokio::test]
                async fn issue_then_consume_succeeds() {
                    $crate::challenge::contract::issue_then_consume_succeeds($factory()).await;
                }
                #[tokio::test]
                async fn second_consume_is_already_consumed() {
                    $crate::challenge::contract::second_consume_is_already_consumed($factory())
                        .await;
                }
                #[tokio::test]
                async fn consume_unknown_is_not_found() {
                    $crate::challenge::contract::consume_unknown_is_not_found($factory()).await;
                }
                #[tokio::test]
                async fn consume_expired_is_expired() {
                    $crate::challenge::contract::consume_expired_is_expired($factory()).await;
                }
                #[tokio::test]
                async fn double_issue_is_already_issued() {
                    $crate::challenge::contract::double_issue_is_already_issued($factory()).await;
                }
                #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
                async fn concurrent_consumes_yield_exactly_one_winner() {
                    $crate::challenge::contract::concurrent_consumes_yield_exactly_one_winner(
                        $factory(),
                    )
                    .await;
                }
            }
        };
    }
}

#[cfg(test)]
crate::challenge_store_contract_cases!(in_memory, crate::challenge::InMemoryChallengeStore::new);

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutate exactly one bound field and assert the commitment changes. This
    /// is the binding property: a challenge issued for one operation can never
    /// be replayed to authorize a different one.
    #[test]
    fn commitment_changes_if_any_bound_field_changes() {
        let base = contract::preimage(1, 10_000);
        let base_commitment = base.commitment();

        type Mutator = fn(&mut ChallengePreimage);
        let mutators: Vec<(&str, Mutator)> = vec![
            ("rp_id", |p| p.rp_id = "evil.example".to_string()),
            ("expected_origin", |p| {
                p.expected_origin = "https://evil.example".to_string()
            }),
            ("tenant", |p| p.tenant = TenantId::new("tenant-b")),
            ("user", |p| p.user = UserId::new("user-2")),
            ("scope", |p| p.scope = ScopeId::new("scope-y")),
            ("actor", |p| p.actor = ActorId::new("actor-8")),
            ("credential_id", |p| {
                p.credential_id = CredentialId::new(vec![0xff; 16])
            }),
            ("run_id", |p| p.run_id = RunId::new("run-99")),
            ("gate_ref", |p| p.gate_ref = GateRef::new("gate:xyz")),
            ("key_or_account_id", |p| {
                p.key_or_account_id = KeyOrAccountId::new("0xdef")
            }),
            ("chain_id", |p| p.chain_id = ChainId::new("eip155:10")),
            ("expiry_ms", |p| p.expiry_ms = 99_999),
            ("delivery_attempt", |p| {
                p.delivery_attempt = DeliveryAttemptId::new("attempt-2")
            }),
            ("rendered_tx_digest", |p| {
                p.rendered_tx_digest = ApprovedTxHash::from_bytes([0xaa; 32])
            }),
        ];

        for (field, mutate) in mutators {
            let mut p = base.clone();
            mutate(&mut p);
            assert_ne!(
                p.commitment(),
                base_commitment,
                "mutating `{field}` must change the challenge commitment"
            );
        }
    }

    #[test]
    fn encode_is_deterministic_across_calls_and_serde() {
        let p = contract::preimage(7, 12_345);
        assert_eq!(p.encode(), p.encode());
        let json = serde_json::to_string(&p).expect("ser");
        let back: ChallengePreimage = serde_json::from_str(&json).expect("de");
        assert_eq!(back.encode(), p.encode());
        assert_eq!(back.commitment(), p.commitment());
    }

    #[test]
    fn issued_and_consumed_round_trip_serde() {
        let ch = contract::issued("c-serde", 9, 10_000);
        let json = serde_json::to_string(&ch).expect("ser");
        let back: IssuedChallenge = serde_json::from_str(&json).expect("de");
        assert_eq!(back, ch);
    }
}
