use base64::{engine::general_purpose, Engine as _};
use candid::{CandidType, Principal};
use hex;
use ic_cdk::{
    api::management_canister::http_request::{
        http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse,
        TransformArgs, TransformContext,
    },
    caller,
};
// use ic_cdk::export::{candid::CandidType, Principal};
use ic_evm_sign;
use ic_evm_sign::state::Environment;
use regex::Regex;
use rsa::{
    pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::cell::RefCell;
mod utils;
use candid::utils::*;
use utils::*;

#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct SignedDkimPublicKey {
    pub selector: String,
    pub domain: String,
    pub chain_id: u64,
    pub tag: String,
    pub signature: String,
    pub public_key: String,
    pub public_key_hash: String,
}

#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct CanisterState {
    pub address: String,
    pub poseidon_canister_id: String,
}

thread_local! {
    pub static CANISTER_STATE: RefCell<CanisterState> = RefCell::new(CanisterState::default());
}

#[ic_cdk::init]
pub async fn init(evn_opt: Option<Environment>, poseidon_canister_id: String) {
    ic_evm_sign::init(evn_opt);
    CANISTER_STATE.with(|s| {
        let mut state = s.borrow_mut();
        state.poseidon_canister_id = poseidon_canister_id;
    });
}

#[ic_cdk::query]
pub async fn get_ethereum_address() -> String {
    let canister_state = CANISTER_STATE.with(|s| s.borrow().clone());
    canister_state.address
}

#[ic_cdk::update]
pub async fn create_ethereum_address() -> Result<String, String> {
    let canister_state = CANISTER_STATE.with(|s| s.borrow().clone());
    if canister_state.address != "" {
        return Err("already created".to_string());
    }
    let res = ic_evm_sign::create_address(Principal::anonymous())
        .await
        .expect("create_address failed");
    CANISTER_STATE.with(|s| {
        let mut state = s.borrow_mut();
        state.address = res.address.clone();
    });
    Ok(res.address)
}

#[ic_cdk::update]
pub async fn sign_dkim_public_key(
    chain_id: u64,
    selector: String,
    domain: String,
    tag: String,
) -> Result<SignedDkimPublicKey, String> {
    let public_key = get_dkim_public_key(&selector, &domain).await?;
    ic_cdk::print(format!("public_key {}",public_key));
    let canister_state = CANISTER_STATE.with(|s| s.borrow().clone());
    if canister_state.poseidon_canister_id == "" {
        return Err("poseidon_canister_id unknown".to_string());
    }
    let poseidon_canister_id = Principal::from_text(canister_state.poseidon_canister_id).unwrap();
    // let req = PoseidonRequest {
    //     preimage_hex: public_key.clone()
    // };
    let (res,): (Result<String,String>,) = ic_cdk::call(
        poseidon_canister_id,
        "public_key_hash",
        (public_key.clone(),),
    )
    .await
    .map_err(|(code, e)| {
        format!(
            "calling poseidon canister failed. code: {:?}, reason: {}",
            code, e
        )
    })?;
    let public_key_hash_hex = res?;
    if tag.contains(";") {
        return Err("tag contains ;".to_string());
    }
    let message = format!(
        "selector={};domain={};tag={};public_key_hash={};",
        selector, domain, tag, public_key_hash_hex
    );
    let signature = sign(message, chain_id).await?;

    let res = SignedDkimPublicKey {
        selector,
        domain,
        chain_id,
        tag,
        signature,
        public_key,
        public_key_hash: public_key_hash_hex,
    };
    Ok(res)
}

async fn sign(message: String, chain_id: u64) -> Result<String, String> {
    let signature = ic_evm_sign::sign_msg(
        message.as_bytes().to_vec(),
        chain_id,
        Principal::anonymous(),
    )
    .await?;
    Ok(signature)
    // let request = SignWithECDSARequest {
    //     message_hash: sha256(&message).to_vec(),
    //     derivation_path: vec![],
    //     key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
    // };

    // let (response,): (SignWithECDSAReply,) = ic_cdk::api::call::call_with_payment(
    //     mgmt_canister_id(),
    //     "sign_with_ecdsa",
    //     (request,),
    //     25_000_000_000,
    // )
    // .await
    // .map_err(|e| format!("sign_with_ecdsa failed {}", e.1))?;

    // Ok(response.signature)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use easy_hasher::easy_hasher::raw_keccak256;
    use ethers_core::types::*;
    use poseidon::public_key_hash;

    #[test]
    fn test_sign_dkim_public_key() {
        // The following values are obtained by running the canister locally.
        let selector = "20230601";
        let domain = "gmail.com";
        let tag = "test";
        let public_key = "0x9edbd2293d6192a84a7b4c5c699d31f906e8b83b09b817dbcbf4bcda3c6ca02fd2a1d99f995b360f52801f79a2d40a9d31d535da1d957c44de389920198ab996377df7a009eee7764b238b42696168d1c7ecbc7e31d69bf3fcc337549dc4f0110e070cec0b111021f0435e51db415a2940011aee0d4db4767c32a76308aae634320642d63fe2e018e81f505e13e0765bd8f6366d0b443fa41ea8eb5c5b8aebb07db82fb5e10fe1d265bd61b22b6b13454f6e1273c43c08e0917cd795cc9d25636606145cff02c48d58d0538d96ab50620b28ad9f5aa685b528f41ef1bad24a546c8bdb1707fb6ee7a2e61bbb440cd9ab6795d4c106145000c13aeeedd678b05f";
        let pk_hash = "0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788";
        assert_eq!(public_key_hash(public_key.to_string()).unwrap(),pk_hash);
        let expected_msg = format!(
            "selector={};domain={};tag={};public_key_hash={};",
            selector, domain, tag, pk_hash
        );
        let signature = Signature::from_str("0x27910c52929ea56c34e9b4913708e1d511864ed4ad739589fc66ec88853934fa1bed43808e2862b13652cccf4f839aee0bf33eb7a9512da544263d93309bda6526").unwrap();
        let recovered = signature.recover(expected_msg).unwrap();
        assert_eq!(
            recovered,
            H160::from_slice(&hex::decode("1882ddedf1d0acc9da2cd67d4e5fa30f0ccfcd8b").unwrap())
        );
    }
}
