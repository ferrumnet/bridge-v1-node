use super::validator::Validator;
use crate::types::errors::{BResult, BError};
use crate::database::mongo::Database;
use crate::types::types::{WithdrawItem, WithdrawItemSignature};
use async_trait::async_trait;

#[async_trait(?Send)]
pub trait Processor {
    async fn process_for_network(&self, network: &String) -> BResult<()>;
    async fn process_withdraw_item(&self, wi: &WithdrawItem) -> BResult<()>;
}

pub struct SwapProcessor<V: Validator, D: Database> {
    validator: Box<V>,
    db: Box<D>,
}

impl<V: Validator, D: Database> SwapProcessor<V, D> {
    pub fn new(validator: V, db: D) -> Self {
        SwapProcessor {
            validator: Box::new(validator),
            db: Box::new(db),
        }
    }
}

#[async_trait(?Send)]
impl<V: Validator, D: Database> Processor for SwapProcessor<V, D> {
    async fn process_for_network(&self, network: &String) -> BResult<()> {
        let withdraw_items = self.db.pending_withdraw_items(network)
            .await
            .map_err(|_| BError::new("Error getting withdraw items"))?;
        for wi in &withdraw_items {
            self.process_withdraw_item(wi).await?
        }
        Ok(())
    }

    async fn process_withdraw_item(&self, wi: &WithdrawItem) -> BResult<()> {
        let sigs = self.db.signed_swaps(
            &wi.receive_network, &wi.receive_transaction_id)
            .await
            .map_err(|_| BError::new("Cannot get signed swaps"))?;
        if self.validator.is_multi_sig_valid(&wi.pay_by_sig.hash, &sigs) {
            let final_sig = self.validator.produce_our_signature(
                &wi.pay_by_sig.hash, &sigs)
                .map_err(|_| BError::new("Error producing the signature"))?;
            let wis = WithdrawItemSignature {
                signature: final_sig.signature.clone(),
                creation_time: final_sig.creation_time,
                creator: final_sig.signer,
            };
            self.db.add_signature_to_withdraw_item(
                &wi.receive_network,
                &wi.receive_transaction_id,
                wi.v,
                &wis,
            ).await
            .map_err(|_| BError::new("Error adding signature to withdraw item"))?;
        }
        Ok(())
    }
}
