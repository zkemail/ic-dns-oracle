#![allow(non_snake_case, non_upper_case_globals)]
use candid::{CandidType, Principal};
use hex;
use ic_cdk::{
    api::management_canister::http_request::{
        http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse,
        TransformArgs, TransformContext,
    },
    caller,
};
use ic_evm_sign;
use ic_evm_sign::state::Environment;
use ic_storage::IcStorage;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    pkcs8::DecodePublicKey,
    traits::{PrivateKeyParts, PublicKeyParts},
    BigUint, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
// use serde_json::{self, Value};
use std::{cell::RefCell, collections::HashMap};
mod utils;
use candid::utils::*;
// use ic_cdk::api::management_canister::main::*;
use utils::*;
use ic_exports::*;


#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct SignedDkimPublicKey {
    pub selector: String,
    pub domain: String,
    pub signature: String,
    pub public_key: String,
    pub public_key_hash: String,
}

#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct SignedRevocation {
    pub selector: String,
    pub domain: String,
    pub signature: String,
    pub public_key: String,
    pub public_key_hash: String,
    pub private_key: String,
}

#[derive(Default, IcStorage, Debug)]
pub struct CanisterState {
    pub address: String,
    pub poseidon_canister_id: String,
    pub dns_client_canister_id: String,
}

#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct DomainState {
    pub previous_response: Option<SignedDkimPublicKey>,
}

#[ic_cdk::init]
pub fn init(evn_opt: Option<Environment>, poseidon_canister_id: String, dns_client_canister_id: String) {
    ic_evm_sign::init(evn_opt.clone());
    let state = CanisterState::get();
    state.borrow_mut().poseidon_canister_id = poseidon_canister_id;
    state.borrow_mut().dns_client_canister_id = dns_client_canister_id;
}

#[ic_cdk::query]
pub fn get_ethereum_address() -> String {
    let state = CanisterState::get();
    state.clone().borrow().address.clone()
}

#[ic_cdk::update]
pub async fn sign_dkim_public_key(
    selector: String,
    domain: String,
) -> Result<SignedDkimPublicKey, String> {
    let domain_with_gappssmtp = format!("{}.{}.gappssmtp.com", &domain.replace(".", "-"), &selector);
    let mut error0 = String::new();
    match _sign_dkim_public_key(selector.clone(), domain).await {
        Ok(res) => {
            return Ok(res);
        }
        Err(e) => {
            error0 = e;
        }
    }
    let mut error1 = String::new();
    match _sign_dkim_public_key(selector, domain_with_gappssmtp).await {
        Ok(res) => {
            return Ok(res);
        }
        Err(e) => {
            error1 = e;
        }
    }
    Err(format!("any signing failed. error0: {}, error1: {}", error0, error1))
}

#[ic_cdk::update]
async fn _sign_dkim_public_key(
    selector: String,
    domain: String,
) -> Result<SignedDkimPublicKey, String> {
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    ic_cdk::api::call::msg_cycles_accept128(available_cycles);
    let canister_state = CanisterState::get();
    let mut canister_state = canister_state.borrow_mut();
    if canister_state.address == "" {
        let address = create_ethereum_address().await?;
        canister_state.address = address.clone();
    }
    let dns_client_canister_id =
    Principal::from_text(canister_state.dns_client_canister_id.clone()).unwrap();
    let (public_key,): (Result<String, String>,) = ic_cdk::api::call::call(
        dns_client_canister_id,
        "get_dkim_public_key",
        (&selector, &domain, 40_000_000_000u64, ),
    )
    .await
    .map_err(|(code, e)| format!("dns_client canister error. {:?}, {}", code, e))?;
    let public_key = public_key?;
    assert!(canister_state.poseidon_canister_id != "");
    let poseidon_canister_id =
        Principal::from_text(canister_state.poseidon_canister_id.clone()).unwrap();
    let (res,): (Result<String, String>,) = ic_cdk::api::call::call(
        poseidon_canister_id,
        "public_key_hash",
        (public_key.clone(),),
    )
    .await
    .map_err(|(code, e)| format!("poseidon canister error. {:?}, {}", code, e))?;
    let public_key_hash_hex = res?;
    let message = format!(
        "SET:selector={};domain={};public_key_hash={};",
        selector, domain, public_key_hash_hex
    );
    let signature =
        ic_evm_sign::sign_msg(message.as_bytes().to_vec(), Principal::anonymous()).await?;

    let res = SignedDkimPublicKey {
        selector,
        domain: domain.clone(),
        signature,
        public_key,
        public_key_hash: public_key_hash_hex,
    };
    Ok(res)
}

#[ic_cdk::update]
pub async fn revoke_dkim_public_key(
    selector: String,
    domain: String,
    private_key_der: String,
) -> Result<SignedRevocation, String>  {
    let mut error0 = String::new();
    match _revoke_dkim_public_key(selector.clone(), domain.clone(), private_key_der.clone()).await {
        Ok(res) => {
            return Ok(res);
        }
        Err(e) => {
            error0 = e;
        }
    }
    let domain_with_gappssmtp = format!("{}.{}.gappssmtp.com", &domain.replace(".", "-"), &selector);
    let mut error1 = String::new();
    match _revoke_dkim_public_key(selector, domain_with_gappssmtp, private_key_der).await {
        Ok(res) => {
            return Ok(res);
        }
        Err(e) => {
            error1 = e;
        }
    }
    Err(format!("any revocation failed. error0: {}, error1: {}", error0, error1))
}

async fn _revoke_dkim_public_key(
    selector: String,
    domain: String,
    private_key_der: String,
) -> Result<SignedRevocation, String> {
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    ic_cdk::api::call::msg_cycles_accept128(available_cycles);
    let canister_state = CanisterState::get();
    let canister_state = canister_state.borrow_mut();
    assert!(canister_state.address != "");
    let revoked_public_key = {
        let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der.as_bytes())
            .expect("Invalid format private key");
        let public_key = private_key.to_public_key();
        assert!(public_key.e() == &BigUint::from(65537u64));
        "0x".to_string() + &hex::encode(&public_key.n().to_bytes_be())
    };
    let dns_client_canister_id =
    Principal::from_text(canister_state.dns_client_canister_id.clone()).unwrap();
    let (fetched_public_key,): (Result<String, String>,) = ic_cdk::api::call::call(
        dns_client_canister_id,
        "get_dkim_public_key",
        (&selector, &domain, 40_000_000_000u64, ),
    )
    .await
    .map_err(|(code, e)| format!("dns_client canister error. {:?}, {}", code, e))?;
    let fetched_public_key = fetched_public_key?;
    assert!(revoked_public_key == fetched_public_key);
    assert!(canister_state.poseidon_canister_id != "");
    let poseidon_canister_id =
        Principal::from_text(canister_state.poseidon_canister_id.clone()).unwrap();
    let (res,): (Result<String, String>,) = ic_cdk::api::call::call(
        poseidon_canister_id,
        "public_key_hash",
        (fetched_public_key.clone(),),
    )
    .await
    .map_err(|(code, e)| format!("poseidon canister failed. {:?}, {}", code, e))?;
    let public_key_hash_hex = res?;
    let message = format!(
        "REVOKE:selector={};domain={};public_key_hash={};",
        selector, domain, public_key_hash_hex
    );
    let signature =
        ic_evm_sign::sign_msg(message.as_bytes().to_vec(), Principal::anonymous()).await?;

    let res = SignedRevocation {
        selector,
        domain: domain.clone(),
        // chain_id: canister_state.chain_id,
        signature,
        public_key: fetched_public_key,
        public_key_hash: public_key_hash_hex,
        private_key: private_key_der,
    };
    Ok(res)
}

// #[cfg(test)]
// mod test {
//     use std::str::FromStr;

//     use super::*;
//     use easy_hasher::easy_hasher::raw_keccak256;
//     use ethers_core::types::*;
//     use hex;
//     use poseidon::public_key_hash;
//     use rsa::pkcs1::{der::SecretDocument, EncodeRsaPrivateKey};
//     use rsa::rand_core::OsRng;

//     #[test]
//     fn test_sign_dkim_public_key() {
//         // The following values are obtained by running the canister locally.
//         let selector = "20230601";
//         let domain = "gmail.com";
//         // let timestamp = 1_697_875_531;
//         let public_key = "0x9edbd2293d6192a84a7b4c5c699d31f906e8b83b09b817dbcbf4bcda3c6ca02fd2a1d99f995b360f52801f79a2d40a9d31d535da1d957c44de389920198ab996377df7a009eee7764b238b42696168d1c7ecbc7e31d69bf3fcc337549dc4f0110e070cec0b111021f0435e51db415a2940011aee0d4db4767c32a76308aae634320642d63fe2e018e81f505e13e0765bd8f6366d0b443fa41ea8eb5c5b8aebb07db82fb5e10fe1d265bd61b22b6b13454f6e1273c43c08e0917cd795cc9d25636606145cff02c48d58d0538d96ab50620b28ad9f5aa685b528f41ef1bad24a546c8bdb1707fb6ee7a2e61bbb440cd9ab6795d4c106145000c13aeeedd678b05f";
//         let pk_hash = "0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788";
//         assert_eq!(public_key_hash(public_key.to_string()).unwrap(), pk_hash);
//         let expected_msg = format!(
//             "SET:chain_id={};selector={};domain={};public_key_hash={};",
//             1, selector, domain, pk_hash
//         );
//         println!("expected_msg {}", expected_msg);
//         let len = expected_msg.len();
//         let len_string = len.to_string();
//         const PREFIX: &str = "\x19Ethereum Signed Message:\n";
//         let mut eth_message = Vec::with_capacity(PREFIX.len() + len_string.len() + len);
//         eth_message.extend_from_slice(PREFIX.as_bytes());
//         eth_message.extend_from_slice(len_string.as_bytes());
//         eth_message.extend_from_slice(&expected_msg.as_bytes());
//         println!("hash {}", hex::encode(raw_keccak256(eth_message).to_vec()));
//         let signature = Signature::from_str("0x1989dad50b6635c11d365b7caca70cbeccdf37b201e0bc191d24e0842c9720184d14be94bac0b79213f87bf63daff4d34382ef55aed93688a393bd34330e00f01c").unwrap();
//         let recovered = signature.recover(expected_msg).unwrap();
//         assert_eq!(
//             recovered,
//             H160::from_slice(&hex::decode("1c63df16d1212ecf5d497984dfd1aa23904756ff").unwrap())
//         );
//     }

//     #[test]
//     fn test_private_to_public() {
//         let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
//         let public_key = private_key.to_public_key();
//         let private_key_der = private_key.to_pkcs1_der().unwrap();

//         let public_key_hex = {
//             let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der.as_bytes())
//                 .expect("Invalid format private key");
//             let public_key = private_key.to_public_key();
//             // if public_key.e() != &BigUint::from(65537u64) {
//             //     panic!("e is not 65537");
//             // }
//             assert!(public_key.e() == &BigUint::from(65537u64));
//             "0x".to_string() + &hex::encode(&public_key.n().to_bytes_be())
//         };

//         assert_eq!(
//             public_key_hex,
//             "0x".to_string() + &hex::encode(&public_key.n().to_bytes_be())
//         );
//     }
// }
