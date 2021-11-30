# Bridge V1 Rust Node

This node simulate a multi-sig using the following signature.

 *** Note: Private Key is stored on the server. Be very careful with access management ***

 The node, first checks all the withdraw items that are not signed. Then, for each of them it will query the database for validator signatures. If there are enough signatures, it adds its own super signature to the withdraw item. This will make the withdraw item actionable on-chain.

## Future Security Improvements

1. Find a crypto lib with secure string support
2. Use 2FA to decrypt the private key seurely and keep it in memory (but secured)
3. Support super-multi-sig. Validators sign the validation logic. Super validators add their signature to the withdraw item.

## Build

```
$ cargo build --release
```
