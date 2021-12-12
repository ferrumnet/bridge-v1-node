mod cli;
mod crypto;
mod database;
mod signer;
mod types;
mod validator;
use crate::crypto::crypto_utils::CryptoUtils;
use crate::database::mongo::DatabaseClient;
use crate::signer::key_provider::EnvKeyProvider;
use crate::types::errors::{BError, BResult};
use crate::types::types::AppConfig;
use crate::validator::swap_processor::{Processor, SwapProcessor};
use crate::validator::validator::MultiSigValidator;
use cli::cli::cli;
use signer::service::SignerServiceImpl;
use std::fs;

// MultiSigSigner. This signer just aggregates signatures for a number of other
// signers. Once enough signatures for a message is provided, we just sign it
// without knowing what the msg represents at all.

async fn setup(c: &AppConfig) -> BResult<Box<dyn Processor>> {
    let cr_f = || CryptoUtils::new();
    let signer: SignerServiceImpl = SignerServiceImpl::new(Box::new(cr_f()));
    let kp = EnvKeyProvider::new();
    let validator = MultiSigValidator::new(&c.signer, signer, kp);
    let db = DatabaseClient::new(&c.db)
        .await
        .map_err(|_| BError::new("Error initializing db client"))?;
    let processor = SwapProcessor::new(validator, db);
    Ok(Box::new(processor))
}

#[tokio::main]
async fn main() {
    let opt = cli();
    let confs = match fs::read_to_string(&opt.config) {
        Ok(c) => AppConfig::from_str(&c),
        Err(e) => {
            println!(
                "Error reading config file {}: {}",
                &opt.config.as_path().to_str().unwrap_or(""),
                e
            );
            return;
        }
    };
    let psr = setup(&confs).await;
    let ps = match psr {
        Ok(p) => p,
        Err(e) => {
            println!("Error setting up the environment: {}", &e.msg);
            return;
        }
    };
    match ps.process_for_network(&opt.network).await {
        Ok(r) => r,
        Err(e) => {
            println!(
                "Error processing for the network: {} - {}",
                &opt.network, e.msg
            );
            return;
        }
    }
}

mod test {
    #[allow(unused_imports)]
    use crate::crypto::crypto_utils::{b2h, h2b, private_to_address, CryptoUtils};
    #[allow(unused_imports)]
    use crate::signer::service::{SignerService, SignerServiceImpl};

    #[test]
    fn zero_x_works() {
        let msg1 = String::from("0x123412341234");
        let msg2 = String::from("123412341234");
        let msg3 = String::from("0X123412341234");
        let h1 = h2b(&msg1);
        let h2 = h2b(&msg2);
        let h3 = h2b(&msg3);
        println!(
            "decoded: '{}' vs '{}' and '{}'",
            b2h(&h1),
            b2h(&h2),
            b2h(&h3)
        );
        assert_eq!(&h1, &h2);
        assert_eq!(h2, h3);
    }

    #[test]
    fn test_sign_then_verify() {
        let msg: String =
            String::from("1a15b1ea0d007ed0e4262248d3406e310474b14bb6434266a5f941eaf86081ce");
        let sk: String =
            String::from("915c8bf73c84c0482beef48bb4bf782892d38d57d3c9af32de6af27a54d12c5a");
        let address: String = b2h(&private_to_address(&h2b(&sk)));
        println!("Using address: {}", &address);

        let cr_f = || CryptoUtils::new();
        let signer = SignerServiceImpl::new(Box::new(cr_f()));
        let signed = signer.sign(&msg, &sk);

        println!("Signed message: {}", &signed);
        let verif_addr = signer.recover(&msg, &signed);
        println!("Verified address is: {}", &verif_addr);
    }
}
