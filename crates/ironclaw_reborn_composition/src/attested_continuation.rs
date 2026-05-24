//! Composition-layer implementation of the crypto-free
//! [`AttestedGateContinuationPort`] (attested-signing PR11).
//!
//! This is the bridge between the crypto-free WebUI facade
//! ([`ironclaw_product_workflow`]) and the attested-signing signer-continuation
//! driver assembled in [`crate::attested`] over [`ironclaw_attested_runtime`].
//!
//! The facade has already driven the turn to `AttestedResolved` (the
//! synchronous `RuntimeAttestedResumePort` binding re-check + one-shot resume
//! guard passed). This port runs the heavyweight half:
//!
//! 1. Decode the opaque [`AttestedProofClaim`] into the concrete
//!    [`ironclaw_signing_provider::SigningProof`] for its proof family (mirrors
//!    the legacy monolith `proof_from_input` / `near_proof_from_input` /
//!    WalletConnect decode in `src/channels/web/features/chat/attested.rs`).
//! 2. Call [`AttestedSignerContinuationDriver::continue_after_resolved`], which
//!    reads the authoritative binding persisted on gate raise, claims the
//!    sealed one-shot grant, verifies the proof through the bound provider, and
//!    performs the ledger-guarded broadcast.
//!
//! All verification (signer/hash binding, sealed-grant CAS, ledger idempotency)
//! lives in `ironclaw_attested_runtime` / the providers — this module is decode
//! + dispatch only.

use std::sync::Arc;

use async_trait::async_trait;

use ironclaw_attested_runtime::ContinuationError;
use ironclaw_product_workflow::{
    AttestedContinuationOutcome, AttestedContinuationRejection, AttestedGateContinuationPort,
    AttestedProofClaim, AttestedProofKind,
};
use ironclaw_signing_provider::{
    ApprovedTxHash, GateRef as SigningGateRef, SigningProof, SigningProviderError,
};
use ironclaw_turns::{GateRef, TurnRunId, TurnScope};
use ironclaw_wallet_external::{
    InjectedProofPayload, InjectedScheme, NearAccessKeyScope, NearRedirectProofPayload,
    WalletConnectProofPayload, encode_injected_proof, encode_near_redirect_proof,
    encode_walletconnect_proof,
};
use serde::Deserialize;

use crate::attested::{LocalDevContinuationDriver, RebornAttestedComposition};

/// The concrete EVM transaction type the custodial continuation path needs. The
/// external-wallet ingress (PR11) never drives the custodial path — the wallet
/// already signed — so it always passes `None`. We still need a concrete type to
/// satisfy the generic bound; the custodial transaction wiring is a later
/// concern.
type NoEvmTx = alloy_consensus::TxEip1559;

/// Composition-layer [`AttestedGateContinuationPort`].
///
/// Holds the assembled signer-continuation driver shared with the reborn
/// runtime (the same driver + binding store + ledger the resume port reads).
pub struct RebornAttestedContinuation {
    driver: Arc<LocalDevContinuationDriver>,
}

impl RebornAttestedContinuation {
    /// Build the port over the runtime's attested-signing composition.
    pub fn new(composition: &RebornAttestedComposition) -> Self {
        Self {
            driver: Arc::clone(composition.driver()),
        }
    }
}

#[async_trait]
impl AttestedGateContinuationPort for RebornAttestedContinuation {
    async fn continue_resolved_gate(
        &self,
        _scope: &TurnScope,
        _run_id: TurnRunId,
        gate_ref: &GateRef,
        claim: &AttestedProofClaim,
    ) -> Result<AttestedContinuationOutcome, AttestedContinuationRejection> {
        let proof = decode_proof(claim)?;
        let signing_gate_ref = SigningGateRef::new(gate_ref.as_str());

        // External-wallet path only: the wallet already signed, so no custodial
        // EVM transaction is supplied. The custodial path is selected purely by
        // the authoritative binding's `provider_id` (never by the caller).
        let outcome = self
            .driver
            .continue_after_resolved::<NoEvmTx>(&signing_gate_ref, &proof, None)
            .await
            .map_err(map_continuation_error)?;

        Ok(AttestedContinuationOutcome {
            signer: outcome.signer,
        })
    }
}

/// Decode the opaque WebUI proof claim into the concrete provider proof for its
/// family. Mirrors the legacy monolith wire contract
/// (`src/channels/web/features/chat/attested.rs`): every byte field arrives as
/// lowercase-hex (optionally `0x`-prefixed) and the hash as hex, so we parse the
/// JSON via explicit input structs rather than the payload types directly (the
/// payload's `ApprovedTxHash` serde is a raw byte array, not the hex wire form).
/// A malformed payload fails closed as `MalformedProof`.
fn decode_proof(claim: &AttestedProofClaim) -> Result<SigningProof, AttestedContinuationRejection> {
    match claim.kind {
        AttestedProofKind::InjectedWallet => {
            let input: InjectedWalletProofInput = parse_input(&claim.proof_json)?;
            let scheme = match input.scheme.as_str() {
                "evm" => InjectedScheme::Evm,
                "solana" => InjectedScheme::Solana,
                _ => return Err(AttestedContinuationRejection::MalformedProof),
            };
            let payload = InjectedProofPayload {
                scheme,
                approved_tx_hash: parse_hash(&input.approved_tx_hash)?,
                claimed_signer: input.claimed_signer,
                signature: parse_hex(&input.signature)?,
                public_key: input.public_key.as_deref().map(parse_hex).transpose()?,
            };
            Ok(SigningProof::InjectedProof(encode_injected_proof(&payload)))
        }
        AttestedProofKind::NearRedirect => {
            let input: NearRedirectProofInput = parse_input(&claim.proof_json)?;
            let access_key_scope = match input.access_key_scope {
                NearAccessKeyScopeInput::FullAccess => NearAccessKeyScope::FullAccess,
                NearAccessKeyScopeInput::FunctionCall {
                    receiver_id,
                    method_names,
                } => NearAccessKeyScope::FunctionCall {
                    receiver_id,
                    method_names,
                },
            };
            let payload = NearRedirectProofPayload {
                approved_tx_hash: parse_hash(&input.approved_tx_hash)?,
                account_id: input.account_id,
                public_key: parse_hex(&input.public_key)?,
                signature: parse_hex(&input.signature)?,
                access_key_scope,
                state: input.state,
            };
            Ok(SigningProof::NearRedirectProof(encode_near_redirect_proof(
                &payload,
            )))
        }
        AttestedProofKind::WalletConnect => {
            let input: WalletConnectProofInput = parse_input(&claim.proof_json)?;
            let payload = WalletConnectProofPayload {
                session_topic: input.session_topic,
                approved_tx_hash: parse_hash(&input.approved_tx_hash)?,
                claimed_signer: input.claimed_signer,
                nonce: parse_hex(&input.nonce)?,
                signature: parse_hex(&input.signature)?,
                public_key: input.public_key.as_deref().map(parse_hex).transpose()?,
            };
            Ok(SigningProof::WalletConnectProof(
                encode_walletconnect_proof(&payload),
            ))
        }
    }
}

fn parse_input<T: for<'de> Deserialize<'de>>(
    value: &serde_json::Value,
) -> Result<T, AttestedContinuationRejection> {
    serde_json::from_value(value.clone()).map_err(|_| AttestedContinuationRejection::MalformedProof)
}

/// Parse a 32-byte hex (optionally `0x`-prefixed) approved-tx hash.
fn parse_hash(s: &str) -> Result<ApprovedTxHash, AttestedContinuationRejection> {
    let bytes = parse_hex(s)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AttestedContinuationRejection::MalformedProof)?;
    Ok(ApprovedTxHash::from_bytes(arr))
}

/// Decode a hex string (optionally `0x`-prefixed) to bytes.
fn parse_hex(s: &str) -> Result<Vec<u8>, AttestedContinuationRejection> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err(AttestedContinuationRejection::MalformedProof);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| AttestedContinuationRejection::MalformedProof)
        })
        .collect()
}

/// Wire input for an injected-wallet proof (lowercase-hex fields). Mirrors the
/// legacy `InjectedWalletProofInput`.
#[derive(Debug, Deserialize)]
struct InjectedWalletProofInput {
    scheme: String,
    claimed_signer: String,
    signature: String,
    approved_tx_hash: String,
    #[serde(default)]
    public_key: Option<String>,
}

/// Wire input for a NEAR redirect proof. Mirrors the legacy
/// `NearRedirectProofInput`.
#[derive(Debug, Deserialize)]
struct NearRedirectProofInput {
    account_id: String,
    public_key: String,
    signature: String,
    approved_tx_hash: String,
    access_key_scope: NearAccessKeyScopeInput,
    state: String,
}

/// Wire form of the NEAR access-key scope. Mirrors the legacy
/// `NearAccessKeyScopeInput`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum NearAccessKeyScopeInput {
    FullAccess,
    FunctionCall {
        receiver_id: String,
        #[serde(default)]
        method_names: Vec<String>,
    },
}

/// Wire input for a WalletConnect v2 proof.
#[derive(Debug, Deserialize)]
struct WalletConnectProofInput {
    session_topic: String,
    claimed_signer: String,
    nonce: String,
    signature: String,
    approved_tx_hash: String,
    #[serde(default)]
    public_key: Option<String>,
}

/// Map the driver's [`ContinuationError`] to the sanitized facade rejection.
/// Categories only — no chain, signer, or ledger internals cross this boundary.
fn map_continuation_error(error: ContinuationError) -> AttestedContinuationRejection {
    match error {
        ContinuationError::MissingBinding => AttestedContinuationRejection::MissingBinding,
        ContinuationError::ProviderMismatch { .. } => {
            AttestedContinuationRejection::ProviderMismatch
        }
        ContinuationError::ProofRejected(SigningProviderError::GrantClaimFailed) => {
            // A replayed proof for an already-claimed grant is an idempotency
            // guard outcome, surfaced as a conflict to the client.
            AttestedContinuationRejection::LedgerGuard
        }
        ContinuationError::ProofRejected(_) | ContinuationError::ApprovedHashMismatch => {
            AttestedContinuationRejection::ProofRejected
        }
        ContinuationError::Ledger(_) => AttestedContinuationRejection::LedgerGuard,
        ContinuationError::ChainSigning(_) | ContinuationError::Broadcast { .. } => {
            AttestedContinuationRejection::ProofRejected
        }
    }
}
