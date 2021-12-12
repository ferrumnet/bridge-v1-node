use crate::types::types::{DbConfig, PayBySig, SignedSwap, WithdrawItem, WithdrawItemSignature};
use async_trait::async_trait;
use mongodb::bson::doc;
use mongodb::bson::document::ValueAccessResult;
use mongodb::bson::Document;
use mongodb::error::Result;
use mongodb::{Collection, Cursor};
use tokio_stream::StreamExt;

pub const MONGO_SCHEMA_VERSION: &str = "2.0";

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
    withdraw_items: Box<Collection>,
    validator_signatures: Box<Collection>,
}

impl DatabaseClient {
    pub async fn new(conf: &DbConfig) -> Result<Self> {
        // let options =
        //     ClientOptions::
        // (&client_uri, ResolverConfig::())
        //         .await?;
        let client = mongodb::Client::with_uri_str(&conf.connection_string).await?;

        let withdraw_items = Box::new(
            client
                .database(&conf.database)
                .collection("userBridgeWithdrawableBalanceItem"),
        );
        let validator_signatures = Box::new(
            client
                .database(&conf.database)
                .collection("validatorSignatures"),
        );
        Ok(DatabaseClient {
            withdraw_items,
            validator_signatures,
        })
    }

    fn doc_to_withdraw_item(&self, d: &Document) -> ValueAccessResult<WithdrawItem> {
        let dpbs = d.get_document("payBySig")?;
        let sigs = dpbs.get_array("signatures");
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

        let pay_by_sig = PayBySig {
            swap_tx_id: String::from(d.get_str("swapTxId")?),
            hash: String::from(d.get_str("hash")?),
            contract_name: String::from(d.get_str("contractName")?),
            contract_version: String::from(d.get_str("contractVersion")?),
            contract_address: String::from(d.get_str("contractAddress")?),
            signatures,
            source_chain_id: d.get_i32("sourceChainId")?,
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
        Ok(SignedSwap {
            creation_time: d.get_i64("creationTime")?,
            signature: String::from(d.get_str("signature")?),
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
            "creator": &wis.creator,
            "signature": &wis.signature,
        };
        let res: Option<Document> = self
            .withdraw_items
            .find_one_and_update(
                doc! {
                    "$and": [
                        { "network": network, },
                        { "transactionId": transaction_id },
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
                        { "network": network, },
                        { "signatures": 0 },
                    ]
                },
                None,
            )
            .await?;

        let mut result: Vec<WithdrawItem> = Vec::new();
        while let Some(doc) = cursor.next().await {
            result.push(self.doc_to_withdraw_item(&doc?).unwrap());
        }
        Ok(result)
    }
}
