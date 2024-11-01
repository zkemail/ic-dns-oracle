# ic_dns_oracle
## Introduction
This is an ICP canister that generates a signature for a pair of a domain and a hash of a DKIM public key registered on the distributed name service (DNS).
The signature can be verified on Ethereum, allowing smart contracts on Ethereum to verify that the given domain and public key hash are registered on the DNS.
For example, this is used in ZK Email to update a dkim registry contract, which stores the authorized public key hashes accessed during email proof verification.

Our repository contains the implementations of theee canisters as follows:
- Poseidon hash canister: this simply computes the Poseidon hash of the given RSA public key.
- DNS client canister: this fetches an RSA public key for the given selector and domain from Google DNS.
- IC DNS oracle backend canister: this is our main canister that generates an ECDSA signature for the fetched public key corresponding to the given selector and domain. The output signature can be verified by smart contracts on Ethereum.

## How to try our canister
Our IC DNS oracle backend canister is available at https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=fxmww-qiaaa-aaaaj-azu7a-cai.
Once you prepare your identity and wallet on ICP, you can obtain the signature for the hash of the public key registered on DNS for the pair of the selector 20230601 and the domain gmail.com by calling the following command:
```
dfx canister call fxmww-qiaaa-aaaaj-azu7a-cai sign_dkim_public_key '("20230601", "gmail.com")'  --network ic --with-cycles 39246898590 --wallet <YOUR_WALLET_CANISTER_ID>
``` 

You can verify it as the ECDSA signature from 0x6293a80bf4bd3fff995a0cab74cbf281d922da02, which is the signer's Ethereum address output by the `get_signer_ethereum_address` function.

## How to run tests
First of all, you need to prepare the binary of `pocket-ic` according to the instruction [here](https://github.com/dfinity/pocketic?tab=readme-ov-file#download-the-pocketic-server).
After you put the binary under the `ic-dns-oracle` directory or set the `POCKET_IC_BIN` to the path to that binary, you can run tests by the following commands:
```
cargo build --target wasm32-unknown-unknown

cargo test
``` 

## References
- [Quick Start](https://internetcomputer.org/docs/quickstart/quickstart-intro)
- [SDK Developer Tools](https://internetcomputer.org/docs/developers-guide/sdk-guide)
- [Rust Canister Devlopment Guide](https://internetcomputer.org/docs/rust-guide/rust-intro)
- [ic-cdk](https://docs.rs/ic-cdk)
- [ic-cdk-macros](https://docs.rs/ic-cdk-macros)
- [Candid Introduction](https://internetcomputer.org/docs/candid-guide/candid-intro)

## Acknowledgment
We sincerely thank [Clank Pan](https://x.com/clankpan) for generously sharing insights and feedback on ICP, which helped us improve our library.