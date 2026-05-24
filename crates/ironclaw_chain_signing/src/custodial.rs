//! The custodial signer: the orchestration that turns a resolved attestation +
//! a persisted decoded transaction into a signed, broadcast transaction, behind
//! two independent enforcement points and the broadcast-idempotency guard.
//!
//! ## Enforcement points
//!
//! 1. **Grant claim (authorization).** The signer refuses to do anything
//!    without successfully claiming the sealed one-shot `AttestedSigningGrant`
//!    (PR3) for this `(context, approved_tx_hash)`. The claim is a one-shot CAS:
//!    a replayed approval cannot be turned into a second signature.
//!
//! 2. **Sign-time approved-tx-hash re-check (integrity).** The signer
//!    re-derives the canonical signing bytes and recomputes the
//!    `ApprovedTxHash` *from the persisted decoded transaction* and asserts it
//!    equals the approved hash the grant was sealed against. If the persisted
//!    decoded tx was mutated after approval, the recomputed hash diverges and
//!    signing fails closed — **before any key is consumed**.
//!
//! On top of these, the [`SigningLedger`] (PR3) enforces broadcast idempotency:
//! the signer advances `Approved -> Signing -> Signed -> BroadcastSubmitted ->
//! (Finalized | Unknown | ManualReview)` and the ledger refuses to re-enter
//! signing for a gate_ref already past `BroadcastSubmitted`, surviving a
//! `Stuck -> InProgress` job recovery.

use std::sync::Arc;

use ironclaw_attestation::{
    DecodedTransaction, GrantKey, RenderingSchemaVersion, SealedGrantStore, SigningLedger,
    SigningLedgerState, canonical_signing_bytes, compute_approved_tx_hash, render,
};
use ironclaw_host_api::ResourceScope;
use ironclaw_signing_provider::{ApprovedTxHash, SigningContext};

use crate::chain::{ChainFamily, ChainKeyId};
use crate::error::ChainSigningError;
use crate::keystore::{ConsumedChainKey, KeyStore};
use crate::kms::ShipGate;
use crate::policy::{CustodyDecision, KeyCustodyPolicy};

/// Inputs to a custodial signing operation. Every value is already persisted /
/// resolved by the higher layers; the signer re-derives the binding hash from
/// `decoded` rather than trusting any caller-supplied hash beyond the approved
/// one it must match.
pub struct CustodialSignRequest {
    /// The signing context (who/what/where/which gate).
    pub context: SigningContext,
    /// Owner scope used to address the keystore + chain AAD.
    pub scope: ResourceScope,
    /// Chain the key is bound to.
    pub chain: ChainKeyId,
    /// The persisted decoded transaction (PR2 model). Enforcement point #2
    /// recomputes the hash from THIS.
    pub decoded: DecodedTransaction,
    /// The `ApprovedTxHash` recorded at approval time (what the grant was sealed
    /// against). The signer recomputes from `decoded` and asserts equality.
    pub approved_tx_hash: ApprovedTxHash,
    /// Schema version the approval was rendered under.
    pub schema_version: RenderingSchemaVersion,
}

/// What a successful signing produced. The chain-native signature bytes are
/// returned for the per-chain broadcast path; the ledger has already been
/// advanced to `Signed`.
#[derive(Debug)]
pub struct CustodialSignOutcome {
    /// Raw chain-native signature bytes.
    pub signature: Vec<u8>,
    /// The signer/account the signature recovered to (public).
    pub signer: String,
}

/// The custodial signer, wired with a keystore, grant store, ledger, ship-gate,
/// and an injectable custody policy.
pub struct CustodialSigner<K, G, L> {
    keystore: Arc<K>,
    grants: Arc<G>,
    ledger: Arc<L>,
    ship_gate: ShipGate,
    custody_policy: Arc<dyn KeyCustodyPolicy>,
}

impl<K, G, L> CustodialSigner<K, G, L>
where
    K: KeyStore,
    G: SealedGrantStore,
    L: SigningLedger,
{
    /// Construct a custodial signer.
    pub fn new(
        keystore: Arc<K>,
        grants: Arc<G>,
        ledger: Arc<L>,
        ship_gate: ShipGate,
        custody_policy: Arc<dyn KeyCustodyPolicy>,
    ) -> Self {
        Self {
            keystore,
            grants,
            ledger,
            ship_gate,
            custody_policy,
        }
    }

    /// Run the two enforcement points and consume the chain key, returning the
    /// decrypted key ONLY if both pass. Splitting this out keeps the
    /// "no key access on failure" property obvious: every early return here
    /// happens before the keystore `consume`.
    async fn authorize_and_consume_key(
        &self,
        req: &CustodialSignRequest,
        requested_family: ChainFamily,
    ) -> Result<ConsumedChainKey, ChainSigningError> {
        // --- Ship-gate (threat #18): refuse mainnet hot-key custodial. ---
        self.ship_gate.authorize_chain(req.chain.as_str())?;

        // --- Injectable custody policy (deny-first defaults). ---
        if let CustodyDecision::Deny { reason } =
            self.custody_policy.authorize_sign(&req.context, &req.chain)
        {
            return Err(ChainSigningError::PolicyDenied { reason });
        }

        // --- Wrong-chain confusion (typed half): the decoded tx variant must
        //     match the bound chain family before anything else. ---
        let tx_family = ChainFamily::of_transaction(&req.decoded);
        if tx_family != requested_family || requested_family != req.chain.family() {
            return Err(ChainSigningError::ChainMismatch {
                bound: req.chain.to_string(),
                requested: req.decoded.chain_tag().to_string(),
            });
        }

        // --- Enforcement point #1: claim the sealed one-shot grant. ---
        // Refuse to sign without a successfully-claimed grant. A second claim
        // of the same grant fails (one-shot), so a replayed approval cannot
        // produce a second signature.
        let grant_key = GrantKey::from_context(&req.context, req.approved_tx_hash);
        self.grants.claim(&grant_key).await?; // GrantError -> ChainSigningError

        // --- Enforcement point #2: sign-time approved-tx-hash re-check. ---
        // Recompute the binding hash FROM THE PERSISTED decoded tx and compare
        // to the approved hash. Any post-approval mutation of `decoded` diverges
        // the hash and fails closed BEFORE the key is consumed.
        let recomputed = recompute_approved_hash(&req.decoded, req.schema_version);
        if recomputed != req.approved_tx_hash {
            return Err(ChainSigningError::ApprovedHashMismatch);
        }

        // --- Both enforcement points passed: consume the chain key. ---
        // The keystore re-checks the chain family and decrypts under the chain
        // AAD (crypto wrong-chain defense).
        self.keystore
            .consume(&req.scope, &req.chain, requested_family)
            .await
            .map_err(|e| ChainSigningError::KeyStore {
                reason: e.to_string(),
            })
    }

    /// Drive the full custodial signing flow for an EVM transaction.
    ///
    /// The flow: authorize (both enforcement points) -> consume key -> advance
    /// ledger `Approved -> Signing` -> sign with ecrecover binding check ->
    /// advance `Signing -> Signed`. Broadcast is performed by the caller via
    /// [`Self::mark_broadcast_submitted`] / [`Self::finalize`] so the ledger
    /// transition and the network submit stay paired.
    pub async fn sign_evm<T>(
        &self,
        req: &CustodialSignRequest,
        tx: &T,
    ) -> Result<CustodialSignOutcome, ChainSigningError>
    where
        T: alloy_consensus::SignableTransaction<alloy_primitives::Signature>,
    {
        let consumed = self
            .authorize_and_consume_key(req, ChainFamily::Evm)
            .await?;

        // Advance the ledger into Signing only after authorization succeeds, so
        // a rejected request never moves the ledger.
        self.ledger
            .advance(&req.context.gate_ref, SigningLedgerState::Signing)
            .await?;

        let key = crate::evm::signing_key_from_bytes(consumed.expose_private_key())?;
        let bound = bound_evm_address(&consumed)?;
        let signed = crate::evm::sign_with_binding_check(tx, &key, bound)?;
        // `consumed` (and the decrypted key) drops here.

        self.ledger
            .advance(&req.context.gate_ref, SigningLedgerState::Signed)
            .await?;

        Ok(CustodialSignOutcome {
            signature: signed.signature.as_bytes().to_vec(),
            signer: format!("0x{}", hex_lower(signed.recovered.as_slice())),
        })
    }

    /// Advance the ledger to `BroadcastSubmitted`. Call this immediately after
    /// the network accepts the signed transaction. The ledger refuses this for
    /// any gate_ref not currently at `Signed`, and refuses re-entry to signing
    /// afterwards (broadcast idempotency).
    pub async fn mark_broadcast_submitted(
        &self,
        ctx: &SigningContext,
    ) -> Result<(), ChainSigningError> {
        self.ledger
            .advance(&ctx.gate_ref, SigningLedgerState::BroadcastSubmitted)
            .await
            .map_err(Into::into)
    }

    /// Advance the ledger to a terminal state after broadcast.
    pub async fn finalize(
        &self,
        ctx: &SigningContext,
        terminal: SigningLedgerState,
    ) -> Result<(), ChainSigningError> {
        if !terminal.is_terminal() {
            return Err(ChainSigningError::Ledger(
                ironclaw_attestation::LedgerError::InvalidTransition {
                    from: SigningLedgerState::BroadcastSubmitted,
                    to: terminal,
                },
            ));
        }
        self.ledger
            .advance(&ctx.gate_ref, terminal)
            .await
            .map_err(Into::into)
    }
}

/// Recompute the binding [`ApprovedTxHash`] from a decoded transaction, exactly
/// as PR2 computed it at approval time (render ∥ canonical ∥ signer ∥ network ∥
/// type ∥ schema). Used by enforcement point #2.
pub fn recompute_approved_hash(
    tx: &DecodedTransaction,
    schema_version: RenderingSchemaVersion,
) -> ApprovedTxHash {
    let rendered = render(tx, schema_version);
    let canonical = canonical_signing_bytes(tx, schema_version);
    compute_approved_tx_hash(
        &rendered,
        &canonical,
        &tx.signer_account(),
        &tx.chain_network(),
        &tx.tx_type_label(),
        schema_version,
    )
}

/// Parse the bound EVM address (hex, no `0x`) from a consumed key's binding.
fn bound_evm_address(
    consumed: &ConsumedChainKey,
) -> Result<alloy_primitives::Address, ChainSigningError> {
    let hex = consumed
        .binding()
        .public_address_hex
        .trim_start_matches("0x");
    let bytes = hex_decode_20(hex).ok_or_else(|| ChainSigningError::KeyStore {
        reason: "bound EVM address is not 20 hex bytes".to_string(),
    })?;
    Ok(alloy_primitives::Address::from(bytes))
}

fn hex_decode_20(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    let bytes = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = nibble(bytes[i * 2])?;
        let lo = nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}
