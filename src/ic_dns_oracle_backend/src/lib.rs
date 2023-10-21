#![allow(non_snake_case, non_upper_case_globals)]
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
use ic_storage::IcStorage;
use regex::Regex;
use rsa::{
    pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::{cell::RefCell, collections::HashMap};
mod utils;
use candid::utils::*;
use ic_exports::*;
use ic_log::{init_log, LogSettings, LoggerConfig};
use log::{debug, error, info};
use utils::*;

#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct SignedDkimPublicKey {
    pub selector: String,
    pub domain: String,
    pub chain_id: u64,
    pub timestamp: u64,
    pub signature: String,
    pub public_key: String,
    pub public_key_hash: String,
}

#[derive(Default, IcStorage, Debug)]
pub struct CanisterState {
    pub address: String,
    pub poseidon_canister_id: String,
    pub chain_id: u64,
    pub domain_states: HashMap<String, DomainState>,
}

#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct DomainState {
    // pub nonce: u64,
    pub previous_response: Option<SignedDkimPublicKey>,
}

// thread_local! {
//     pub static CANISTER_STATE: RefCell<CanisterState> = RefCell::new(CanisterState::default());
// }

#[ic_cdk::init]
pub async fn init(
    evn_opt: Option<Environment>,
    poseidon_canister_id: String,
    chain_id: u64,
    domains: Vec<String>,
) {
    ic_evm_sign::init(evn_opt);
    Principal::from_text(poseidon_canister_id.clone()).unwrap();
    let state = CanisterState::get();
    state.borrow_mut().poseidon_canister_id = poseidon_canister_id;
    state.borrow_mut().chain_id = chain_id;
    for domain in domains {
        state
            .borrow_mut()
            .domain_states
            .insert(domain, DomainState::default());
    }
    let settings = LogSettings {
        in_memory_records: Some(128),
        log_filter: Some("info".to_string()),
        enable_console: true,
    };
    init_log(&settings).expect("Failed to initialize logger");
    info!("init");
}

#[ic_cdk::query]
pub async fn get_ethereum_address() -> String {
    let state = CanisterState::get();
    info!("state {:?}", state.clone());
    state.clone().borrow().address.clone()
}

#[ic_cdk::query]
pub async fn get_previous_response(
    domain: String,
    // nonce: u64,
) -> Result<SignedDkimPublicKey, String> {
    let canister_state = CanisterState::get();
    info!("state {:?}", canister_state.clone());
    let canister_state = canister_state.borrow();
    let domain_state = match canister_state.domain_states.get(&domain) {
        Some(s) => s,
        None => return Err(format!("domain {} not found", domain).to_string()),
    };
    // if nonce >= domain_state.nonce {
    //     return Err(format!("nonce {} too large", nonce).to_string());
    // }
    match domain_state.previous_response.as_ref() {
        Some(s) => Ok(s.clone()),
        None => Err("previous_respons not found".to_string()),
    }
}

// #[ic_cdk::update]
// pub async fn create_ethereum_address() -> Result<String, String> {
//     let canister_state = CANISTER_STATE.with(|s| s.borrow().clone());
//     if canister_state.address != "" {
//         return Err("already created".to_string());
//     }
//     let res = ic_evm_sign::create_address(Principal::anonymous())
//         .await
//         .expect("create_address failed");
//     CANISTER_STATE.with(|s| {
//         let mut state = s.borrow_mut();
//         state.address = res.address.clone();
//     });
//     Ok(res.address)
// }

#[ic_cdk::update]
pub async fn sign_dkim_public_key(
    selector: String,
    domain: String,
) -> Result<SignedDkimPublicKey, String> {
    info!("cycle {}", ic_cdk::api::call::msg_cycles_available128());
    let canister_state = CanisterState::get();
    info!("state {:?}", canister_state.clone());
    let mut canister_state = canister_state.borrow_mut();
    // let mut canister_state = CANISTER_STATE.with(|s| s.borrow().clone());
    if canister_state.address == "" {
        let address = create_ethereum_address().await?;
        // let canister_state = CanisterState::get();
        canister_state.address = address.clone();
    }
    let public_key = get_dkim_public_key(&selector, &domain).await?;
    info!("public_key {}", public_key);
    if canister_state.poseidon_canister_id == "" {
        return Err("poseidon_canister_id unknown".to_string());
    }
    info!(
        "poseidon_canister_id {}",
        canister_state.poseidon_canister_id
    );
    let poseidon_canister_id =
        Principal::from_text(canister_state.poseidon_canister_id.clone()).unwrap();
    info!("cycle {}", ic_cdk::api::call::msg_cycles_available128());
    let (res,): (Result<String, String>,) = ic_cdk::call(
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
    info!("cycle {}", ic_cdk::api::call::msg_cycles_available128());
    let public_key_hash_hex = res?;
    let timestamp = ic_cdk::api::time();
    let timestamp_sec = timestamp / 1_000_000_000;
    info!("timestamp {}", timestamp_sec);
    let message = format!(
        "chain_id={};selector={};domain={};timestamp={};public_key_hash={};",
        canister_state.chain_id, selector, domain, timestamp_sec, public_key_hash_hex
    );
    let signature = sign(message).await?;

    let res = SignedDkimPublicKey {
        selector,
        domain: domain.clone(),
        chain_id: canister_state.chain_id,
        timestamp: timestamp_sec,
        signature,
        public_key,
        public_key_hash: public_key_hash_hex,
    };
    let mut domain_state = canister_state.domain_states.get_mut(&domain).unwrap();
    domain_state.previous_response = Some(res.clone());
    // CANISTER_STATE.with(|s| {
    //     let mut state = s.borrow_mut();
    //     let domain_states = state.domain_states.get_mut(&domain).unwrap();
    //     domain_states.nonce += 1;
    //     domain_states.previous_responses.push(res.clone());
    // });
    info!("cycle {}", ic_cdk::api::call::msg_cycles_available128());
    Ok(res)
}

async fn sign(message: String) -> Result<String, String> {
    let signature =
        ic_evm_sign::sign_msg(message.as_bytes().to_vec(), Principal::anonymous()).await?;
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
    use hex;
    use poseidon::public_key_hash;

    #[test]
    fn test_sign_dkim_public_key() {
        // The following values are obtained by running the canister locally.
        let selector = "20230601";
        let domain = "gmail.com";
        let timestamp = 1_697_875_531;
        let public_key = "0x9edbd2293d6192a84a7b4c5c699d31f906e8b83b09b817dbcbf4bcda3c6ca02fd2a1d99f995b360f52801f79a2d40a9d31d535da1d957c44de389920198ab996377df7a009eee7764b238b42696168d1c7ecbc7e31d69bf3fcc337549dc4f0110e070cec0b111021f0435e51db415a2940011aee0d4db4767c32a76308aae634320642d63fe2e018e81f505e13e0765bd8f6366d0b443fa41ea8eb5c5b8aebb07db82fb5e10fe1d265bd61b22b6b13454f6e1273c43c08e0917cd795cc9d25636606145cff02c48d58d0538d96ab50620b28ad9f5aa685b528f41ef1bad24a546c8bdb1707fb6ee7a2e61bbb440cd9ab6795d4c106145000c13aeeedd678b05f";
        let pk_hash = "0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788";
        assert_eq!(public_key_hash(public_key.to_string()).unwrap(), pk_hash);
        let expected_msg = format!(
            "chain_id={};selector={};domain={};timestamp={};public_key_hash={};",
            1, selector, domain, timestamp, pk_hash
        );
        println!("expected_msg {}", expected_msg);
        let len = expected_msg.len();
        let len_string = len.to_string();
        const PREFIX: &str = "\x19Ethereum Signed Message:\n";
        let mut eth_message = Vec::with_capacity(PREFIX.len() + len_string.len() + len);
        eth_message.extend_from_slice(PREFIX.as_bytes());
        eth_message.extend_from_slice(len_string.as_bytes());
        eth_message.extend_from_slice(&expected_msg.as_bytes());
        println!("hash {}", hex::encode(raw_keccak256(eth_message).to_vec()));
        let signature = Signature::from_str("0x1989dad50b6635c11d365b7caca70cbeccdf37b201e0bc191d24e0842c9720184d14be94bac0b79213f87bf63daff4d34382ef55aed93688a393bd34330e00f01c").unwrap();
        let recovered = signature.recover(expected_msg).unwrap();
        assert_eq!(
            recovered,
            H160::from_slice(&hex::decode("1c63df16d1212ecf5d497984dfd1aa23904756ff").unwrap())
        );
    }
}
