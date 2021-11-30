use std::fmt;
use serde::__private::Formatter;

pub struct WithdrawItemSignature {
    pub creation_time: i64,
    pub creator: String,
    pub signature: String,
}

pub struct PayBySig {
    pub source_chain_id: i32,
    pub swap_tx_id: String,
    pub contract_name: String,
    pub contract_version: String,
    pub contract_address: String,
    pub hash: String,
    pub signatures: Vec<WithdrawItemSignature>
}

pub struct WithdrawItem {
    pub v: String,
    pub version: String,
    pub receive_network: String,
    pub receive_transaction_id: String,
    pub send_network: String,
    pub pay_by_sig: PayBySig,
    pub signatures: i32,
}

pub struct SignedSwap {
    pub creation_time: i64,
    pub network: String,
    pub transaction_id: String,
    pub msg_hash: String,
    pub signer: String,
    pub signature: String,
}

impl fmt::Display for SignedSwap {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {}:{} msg_hash:{}, signer: {}, signature: {}",
               &self.creation_time, &self.network, &self.transaction_id,
            &self.msg_hash, &self.signer, &self.signature)
    }
}

pub struct SignerConfig {
    pub address: String,
    pub validators: Vec<String>,
    pub min_threshold: u32,
}

pub struct DbConfig {
    pub connection_string: String,
    pub database: String,
}