use crate::types::types::{DbConfig, PayBySig, SignedSwap, WithdrawItem, WithdrawItemSignature};
use async_trait::async_trait;
use mongodb::bson::doc;
use mongodb::bson::document::ValueAccessResult;
use mongodb::bson::Document;
use mongodb::error::Result;
use mongodb::{Collection, Cursor};
use tokio_stream::StreamExt;

pub const MONGO_SCHEMA_VERSION: &str = "1.0";

#[async_trait]
pub trait Database {
    async fn add_signature_to_withdraw_item(
        &self,
        network: &String,
        transaction_id: &String,
        _v: i32,
        wis: &WithdrawItemSignature,
    ) -> Result<Document>;

    async fn signed_swaps(
        &self,
        network: &String,
        transaction_id: &String,
    ) -> Result<Vec<SignedSwap>>;

    async fn pending_withdraw_items(&self, network: &String) -> Result<Vec<WithdrawItem>>;
}

pub struct DatabaseClient {
    withdraw_items: Box<Collection<Document>>,
    validator_signatures: Box<Collection<Document>>,
}

impl DatabaseClient {
    pub async fn new(conf: &DbConfig) -> Result<Self> {
        let client = mongodb::Client::with_uri_str(&conf.connection_string).await?;
        // println!("Connected using {}", &conf.connection_string);

        let withdraw_items = Box::new(
            client
                .database(&conf.database)
                .collection("userbridgewithdrawablebalanceitems"),
        );
        let validator_signatures = Box::new(
            client
                .database(&conf.database)
                .collection("withdrawitemhashverifications"),
        );
        Ok(DatabaseClient {
            withdraw_items,
            validator_signatures,
        })
    }

    fn doc_to_withdraw_item(&self, d: &Document) -> ValueAccessResult<WithdrawItem> {
        let dpbs = d.get_document("payBySig")?;
        let sigs = dpbs.get_array("signatures");
        // println!("SIGS {}", &sigs.map_or_else(|e| 0 as usize, |s| s.len()));
        let signatures: Vec<WithdrawItemSignature> = sigs
            .unwrap()
            .into_iter()
            .map(|s| {
                let sig_d = s.as_document().unwrap();
                WithdrawItemSignature {
                    signature: String::from(sig_d.get_str("signature").unwrap()),
                    creator: String::from(sig_d.get_str("creator").unwrap()),
                    creation_time: sig_d.get_i64("creationTime").unwrap(),
                }
            })
            .collect();
        let swap_tx_id = String::from(dpbs.get_str("swapTxId")?);
        let hash = String::from(dpbs.get_str("hash")?);
        let contract_name = String::from(dpbs.get_str("contractName")?);
        let contract_version = String::from(dpbs.get_str("contractVersion")?);
        let contract_address = String::from(dpbs.get_str("contractAddress")?);
        let source_chain_id = dpbs.get_i32("sourceChainId")?;

        let pay_by_sig = PayBySig {
            swap_tx_id,
            hash,
            contract_name,
            contract_version,
            contract_address,
            signatures,
            source_chain_id,
        };
        Ok(WithdrawItem {
            v: d.get_i32("v")?,
            version: String::from(d.get_str("version")?),
            receive_network: String::from(d.get_str("receiveNetwork")?),
            signatures: d.get_i32("signatures")?,
            receive_transaction_id: String::from(d.get_str("receiveTransactionId")?),
            send_network: String::from(d.get_str("sendNetwork")?),
            pay_by_sig,
        })
    }

    fn doc_to_signed_swap(&self, d: &Document) -> ValueAccessResult<SignedSwap> {
        let creation_time = d.get_f64("signatureCreationTime")?;
        let signature = String::from(d.get_str("signature")?);
        Ok(SignedSwap {
            creation_time: creation_time as i64,
            signature,
            signer: String::from(d.get_str("signer")?),
            transaction_id: String::from(d.get_str("transactionId")?),
            network: String::from(d.get_str("network")?),
            msg_hash: String::from(d.get_str("hash")?),
        })
    }
}

#[async_trait]
impl Database for DatabaseClient {
    async fn add_signature_to_withdraw_item(
        &self,
        network: &String,
        transaction_id: &String,
        _v: i32,
        wis: &WithdrawItemSignature,
    ) -> Result<Document> {
        let new_sig = doc! {
            "creationTime": wis.creation_time,
            "creator": wis.creator.clone(),
            "signature": wis.signature.clone(),
        };
        let res: Option<Document> = self
            .withdraw_items
            .find_one_and_update(
                doc! {
                    "$and": [
                        { "receiveNetwork": network.clone(), },
                        { "receiveTransactionId": transaction_id.clone() },
                        { "v": _v },
                    ]
                },
                doc! {
                    "$set": {
                        "signatures": 1,
                        "v": _v + 1, // v is the optimistic locking version
                    },
                    "$push": {
                        "payBySig.signatures": new_sig,
                    }
                },
                None,
            )
            .await?;
        Ok(res.unwrap())
    }

    async fn signed_swaps(
        &self,
        network: &String,
        transaction_id: &String,
    ) -> Result<Vec<SignedSwap>> {
        let mut cursor: Cursor<_> = self
            .validator_signatures
            .find(
                doc! {
                    "$and": [
                        { "network": network, },
                        { "transactionId": transaction_id },
                    ]
                },
                None,
            )
            .await?;

        let mut result: Vec<SignedSwap> = Vec::new();
        while let Some(doc) = cursor.next().await {
            result.push(self.doc_to_signed_swap(&doc?).unwrap());
        }
        Ok(result)
    }

    async fn pending_withdraw_items(&self, network: &String) -> Result<Vec<WithdrawItem>> {
        let mut cursor: Cursor<_> = self
            .withdraw_items
            .find(
                doc! {
                    "$and": [
                        { "version": MONGO_SCHEMA_VERSION, },
                        { "receiveNetwork": network, },
                        { "signatures": 0 },
                    ]
                },
                None,
            )
            .await?;

        let mut result: Vec<WithdrawItem> = Vec::new();
        while let Some(doc) = cursor.next().await {
            println!("Pushing a WI");
            result.push(self.doc_to_withdraw_item(&doc?).unwrap());
        }
        Ok(result)
    }
}
