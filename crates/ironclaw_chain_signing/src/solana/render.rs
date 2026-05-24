//! Solana human render — delegates to the PR2 shared projection so the view and
//! the canonical bytes cannot diverge.

use ironclaw_attestation::{DecodedTransaction, RenderedTx, RenderingSchemaVersion, render};

/// Render a decoded Solana transaction for human approval.
pub fn render_solana(tx: &DecodedTransaction, schema: RenderingSchemaVersion) -> RenderedTx {
    render(tx, schema)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solana::decode::decode_projected;
    use ironclaw_attestation::{Bytes32, SolanaInstruction, SolanaTransaction};

    #[test]
    fn render_surfaces_cluster_blockhash_and_compute_budget() {
        let program = Bytes32([9u8; 32]);
        let tx = SolanaTransaction {
            cluster: "mainnet-beta".into(),
            account_keys: vec![Bytes32([1u8; 32]), program],
            recent_blockhash: Bytes32([2u8; 32]),
            instructions: vec![SolanaInstruction {
                program_id: program,
                accounts: vec![Bytes32([1u8; 32])],
                data: vec![1],
            }],
            compute_unit_limit: Some(200_000),
            compute_unit_price: Some(7),
        };
        let decoded = decode_projected(tx).unwrap();
        let r = render_solana(&decoded, RenderingSchemaVersion::CURRENT);
        assert!(r.has_label("Cluster"));
        assert!(r.has_label("Recent Blockhash"));
        assert!(r.has_label("Compute Unit Limit"));
        assert!(r.has_label("Compute Unit Price (micro-lamports)"));
    }
}
