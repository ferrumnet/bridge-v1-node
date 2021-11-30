mod crypto;
mod signer;
mod types;
mod validator;
mod database;
use signer::service::{SignerServiceImpl, SignerService};
use crate::crypto::crypto_utils::CryptoUtils;
use crate::validator::validator::MultiSigValidator;
use crate::signer::key_provider::EnvKeyProvider;
use crate::types::types::SignerConfig;

// MultiSigSigner. This signer just aggregates signatures for a number of other
// signers. Once enough signatures for a message is provided, we just sign it
// without knowing what the msg represents at all.

fn setup() -> MultiSigValidator<EnvKeyProvider> {
    let cr_f = || CryptoUtils::new();
    let signer: SignerServiceImpl = SignerServiceImpl::new(Box::new(cr_f()));
    let kp = EnvKeyProvider::new();
    let conf = SignerConfig {
        address: String::from("YO"),
        min_threshold: 1,
        validators: Vec::new(),
    };
    let validator = MultiSigValidator::new(
        conf, signer, kp
    );
    validator
}

fn main() {
    let valid = setup();
    valid.is_multi_sig_valid(&String::new(), &Vec::new());
    // println!("Hello, world! {}", signer.sign(
    //     &String::from("BOO"), &String::from("SOO")));
}

mod test {
    use crate::setup;
    use crate::signer::service::{SignerService, SignerServiceImpl};
    use crate::crypto::crypto_utils::{private_to_address, h2b, b2h, CryptoUtils};

    #[test]
    fn zero_x_works() {
        let msg1 = String::from("0x123412341234");
        let msg2 = String::from("123412341234");
        let msg3 = String::from("0X123412341234");
        let h1 = h2b(&msg1);
        let h2 = h2b(&msg2);
        let h3 = h2b(&msg3);
        println!("decoded: '{}' vs '{}' and '{}'", b2h(&h1), b2h(&h2), b2h(&h3));
        assert_eq!(&h1, &h2);
        assert_eq!(h2, h3);
    }

    #[test]
    fn test_sign_then_verify() {
        let msg: String = String::from("1a15b1ea0d007ed0e4262248d3406e310474b14bb6434266a5f941eaf86081ce");
        let sk: String = String::from("915c8bf73c84c0482beef48bb4bf782892d38d57d3c9af32de6af27a54d12c5a");
        let address: String = b2h(&private_to_address(&h2b(&sk)));
        println!("Using address: {}", &address);

        let cr_f = || CryptoUtils::new();
        let signer: SignerServiceImpl = SignerServiceImpl::new(Box::new(cr_f()));
        let signed = signer.sign(&msg, &sk);

        println!("Signed message: {}", &signed);
        let verif_addr = signer.recover(&msg, &signed);
        println!("Verified address is: {}", &verif_addr);
    }
}