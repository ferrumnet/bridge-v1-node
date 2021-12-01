use crate::types::types::{SignedSwap, SignerConfig};
use crate::signer::service::{SignerServiceImpl, SignerService};
use crate::signer::key_provider::KeyProvider;
use std::collections::HashMap;
use crate::types::utils::now;

pub trait Validator {
    fn is_multi_sig_valid(
        &self,
        msg: &String,
        all_signatures: &Vec<SignedSwap>,
    ) -> bool;
    fn verify_sig(&self, msg: &String, s: &SignedSwap) -> bool;
    fn produce_our_signature(
        &self,
        msg: &String,
        signatures: &Vec<SignedSwap>,
    ) -> Result<SignedSwap, ValidatorError>;
}

pub struct ValidatorError {
    pub msg: String,
}

pub struct MultiSigValidator<KP: KeyProvider> {
    config: SignerConfig,
    signing_svc: SignerServiceImpl,
    key_provider: Box<KP>,
}

impl<KP: KeyProvider> MultiSigValidator<KP> {
    pub fn new(
        config: &SignerConfig,
        signing_svc: SignerServiceImpl,
        kp: KP,
    ) -> Self {
        MultiSigValidator {
            config: config.clone(),
            signing_svc,
            key_provider: Box::new(kp),
        }
    }
}

impl<KP: KeyProvider> Validator for MultiSigValidator<KP> {
    /**
    Go through all the sig, make sure they are unique, and share the msg.
    **/
    fn is_multi_sig_valid(
        &self,
        msg: &String,
        all_signatures: &Vec<SignedSwap>,
    ) -> bool {
        let signatures: Vec<&SignedSwap> = all_signatures.into_iter()
            .filter(|s| msg.eq(&s.msg_hash))
            .collect();
        if signatures.len() == 0 {
            return false;
        }
        if signatures.len() <= self.config.min_threshold as usize {
            let sig = &signatures[0];
            println!("ignoring {}:{} - not enough signatures ({} of {})",
                     sig.network, sig.transaction_id, signatures.len(), self.config.min_threshold);
            return false;
        }
        let expected_net = &signatures[0].network;
        let expected_tix = &signatures[0].transaction_id;
        for s in &signatures {
            if expected_net.ne(&s.network) || expected_tix.ne(&s.transaction_id) {
                println!("Error - unexpected network ({}) or transactionId ({}) in {}",
                         &expected_net, &expected_tix, s);
                return false;
            }
        }
        let mut deduped: HashMap<String, &SignedSwap> = HashMap::new();
        signatures.into_iter()
            .for_each(|s| {
                deduped.insert(s.signer.clone(), s);
            });
        if deduped.len() == 0 {
            return false;
        }
        let valid = deduped.values().into_iter()
            .filter(|s| self.verify_sig(&msg, s)).count();
        let meets_thr = valid >= self.config.min_threshold as usize;
        if !meets_thr {
            println!("Could not validate msg '{}' because not enough signatures were available",
                msg);
            return false;
        }
        meets_thr
    }

    fn verify_sig(&self, msg: &String, s: &SignedSwap) -> bool {
        let recovered: String = self.signing_svc.recover(msg, &s.signature);
        if recovered.ne(&s.signer) {
            println!("Error verify signature. Provided signature doesn't match the record {}", s);
            return false;
        }
        // Make sure the recovered signature is configured here
        let valid = &self.config.validators;
        let from_list = valid.into_iter().any(|v| v.eq(&s.signer));
        if !from_list {
            println!("Error! received a signature from '{}', but signer is not configured",
                &s.signer);
            return false;
        }
        true
    }

    fn produce_our_signature(
        &self,
        msg: &String,
        signatures: &Vec<SignedSwap>,
    ) -> Result<SignedSwap, ValidatorError> {
        if !self.is_multi_sig_valid(&msg, &signatures) {
            return Err(ValidatorError{
                msg: String::from("Multisig is not valid")
            });
        }
        let kp: &KP = self.key_provider.as_ref();
        let my_sig = &self.signing_svc.sign(&msg, &kp.get_sk());
        Ok(SignedSwap {
            signer: self.config.address.clone(),
            network: signatures[0].network.clone(),
            transaction_id: signatures[0].transaction_id.clone(),
            msg_hash: msg.clone(),
            creation_time: now(),
            signature: my_sig.clone(),
        })
    }
}