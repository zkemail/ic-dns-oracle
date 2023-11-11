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
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    pkcs8::DecodePublicKey,
    traits::{PrivateKeyParts, PublicKeyParts},
    BigUint, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::{cell::RefCell, collections::HashMap};
mod utils;
use candid::utils::*;
use ic_cdk::api::management_canister::main::*;
use ic_exports::*;
use ic_log::{init_log, LogSettings, LoggerConfig};
use log::{debug, error, info};
use serde_bytes;
use utils::*;

#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct SignedDkimPublicKey {
    pub selector: String,
    pub domain: String,
    pub chain_id: u64,
    // pub timestamp: u64,
    pub signature: String,
    pub public_key: String,
    pub public_key_hash: String,
}

#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct SignedRevocation {
    pub selector: String,
    pub domain: String,
    pub chain_id: u64,
    // pub timestamp: u64,
    pub signature: String,
    pub public_key: String,
    pub public_key_hash: String,
    pub private_key: String,
}

#[derive(Default, IcStorage, Debug)]
pub struct CanisterState {
    pub address: String,
    pub poseidon_canister_id: String,
    pub chain_id: u64,
    pub http_cycles: u128,
    pub poseidon_cycles: u128,
    pub fee_cycles: u128,
    pub domain_states: HashMap<String, DomainState>,
}

#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct DomainState {
    // pub nonce: u64,
    pub previous_response: Option<SignedDkimPublicKey>,
}

#[ic_cdk::init]
pub fn init(evn_opt: Option<Environment>, chain_id: u64, domains: Vec<String>) {
    ic_evm_sign::init(evn_opt.clone());
    // let wasm_module = serde_bytes::ByteBuf::from(wasm_args.wasm_module);
    // let install_arg = InstallCodeArgument {
    //     mode: CanisterInstallMode::Install,
    //     canister_id: Principal::from_text(poseidon_canister_id.clone()).unwrap(),
    //     wasm_module: wasm_bytes,
    //     arg: vec![],
    // };
    // install_code(install_arg)
    //     .await
    //     .expect("fail to install the code to poseidon canister");
    let state = CanisterState::get();
    state.borrow_mut().chain_id = chain_id;
    for domain in domains {
        state
            .borrow_mut()
            .domain_states
            .insert(domain, DomainState::default());
    }
    let http_cycles: u128 = match evn_opt {
        Some(Environment::Development) => 3_600_000_000,
        Some(Environment::Staging) => 40_000_000_000,
        Some(Environment::Production) => 40_000_000_000,
        None => {
            panic!("evn None");
        }
    };
    state.borrow_mut().http_cycles = http_cycles;
    state.borrow_mut().poseidon_cycles = 20_000_000;
    let sign_cycles = ic_evm_sign::state::STATE.with(|s| s.borrow().config.sign_cycles) as u128;
    state.borrow_mut().fee_cycles = http_cycles + 20_000_000 + sign_cycles;
    let settings = LogSettings {
        in_memory_records: Some(128),
        log_filter: Some("info".to_string()),
        enable_console: true,
    };
    init_log(&settings).expect("Failed to initialize logger");
    info!("init");
}

#[ic_cdk::query]
pub fn get_ethereum_address() -> String {
    let state = CanisterState::get();
    info!("state {:?}", state.clone());
    state.clone().borrow().address.clone()
}

#[ic_cdk::query]
pub fn get_previous_response(domain: String) -> Result<SignedDkimPublicKey, String> {
    let canister_state = CanisterState::get();
    info!("state {:?}", canister_state.clone());
    let canister_state = canister_state.borrow();
    let domain_state = match canister_state.domain_states.get(&domain) {
        Some(s) => s,
        None => return Err(format!("domain {} not found", domain).to_string()),
    };
    match domain_state.previous_response.as_ref() {
        Some(s) => Ok(s.clone()),
        None => Err("previous_respons not found".to_string()),
    }
}

#[ic_cdk::query]
pub fn get_supported_domains() -> Vec<String> {
    let canister_state = CanisterState::get();
    info!("state {:?}", canister_state.clone());
    let canister_state = canister_state.borrow();
    canister_state.domain_states.keys().cloned().collect()
}

#[ic_cdk::query]
pub fn get_log_records(count: usize) -> Vec<String> {
    debug!("collecting {count} log records");
    ic_log::take_memory_records(count)
}

#[ic_cdk::inspect_message]
fn inspect_message() {
    match ic_cdk::api::call::method_name().as_str() {
        "create_poseidon_canister" => {
            if ic_cdk::api::is_controller(&ic_cdk::caller()) {
                ic_cdk::api::call::accept_message();
                return;
            } else {
                ic_cdk::api::call::reject_message();
                panic!("call not from controller is not allowed");
            }
        }
        "sign_dkim_public_key" => {
            if ic_cdk::caller() != Principal::anonymous() {
                ic_cdk::api::call::accept_message();
                return;
            } else {
                ic_cdk::api::call::reject_message();
                panic!("call from anonymous is not allowed");
            }
        }
        _ => {
            ic_cdk::api::call::reject_message();
            panic!("not allowed method");
        }
    };
}

#[ic_cdk::update]
pub async fn create_poseidon_canister() -> String {
    let state = CanisterState::get();
    if state.borrow().poseidon_canister_id != "" {
        return state.borrow().poseidon_canister_id.clone();
    }
    let canister_setting = CanisterSettings {
        controllers: Some(vec![ic_cdk::caller(), ic_cdk::api::id()]),
        compute_allocation: None,
        memory_allocation: None,
        freezing_threshold: None,
    };
    let create_arg = CreateCanisterArgument {
        settings: Some(canister_setting),
    };
    let (create_res,) = create_canister(create_arg, 261_538_461_538)
        .await
        .expect("fail to create poseidon canister");
    let poseidon_canister_id = create_res.canister_id.to_text();
    info!("poseidon_canister_id {}", poseidon_canister_id);
    state.borrow_mut().poseidon_canister_id = poseidon_canister_id.clone();
    poseidon_canister_id
}

#[ic_cdk::update]
pub async fn sign_dkim_public_key(
    selector: String,
    domain: String,
) -> Result<SignedDkimPublicKey, String> {
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    let accepted_cycles = ic_cdk::api::call::msg_cycles_accept128(available_cycles);
    if available_cycles != accepted_cycles {
        return Err("not all of the available_cycles is moved".to_string());
    }
    info!("available_cycles {}", available_cycles);
    let canister_state = CanisterState::get();
    info!("state {:?}", canister_state.clone());
    let mut canister_state = canister_state.borrow_mut();
    if available_cycles < canister_state.fee_cycles {
        return Err("not enough cycles".to_string());
    }
    if canister_state.address == "" {
        let address = create_ethereum_address().await?;
        canister_state.address = address.clone();
    }
    let public_key = get_dkim_public_key(&selector, &domain, canister_state.http_cycles).await?;
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
    let (res,): (Result<String, String>,) = ic_cdk::api::call::call_with_payment128(
        poseidon_canister_id,
        "public_key_hash",
        (public_key.clone(),),
        canister_state.poseidon_cycles,
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
    // let timestamp = ic_cdk::api::time();
    // let timestamp_sec = timestamp / 1_000_000_000;
    // info!("timestamp {}", timestamp_sec);
    let message = format!(
        "SET:chain_id={};selector={};domain={};public_key_hash={};",
        canister_state.chain_id, selector, domain, public_key_hash_hex
    );
    let signature = sign(message).await?;

    let res = SignedDkimPublicKey {
        selector,
        domain: domain.clone(),
        chain_id: canister_state.chain_id,
        // timestamp: timestamp_sec,
        signature,
        public_key,
        public_key_hash: public_key_hash_hex,
    };
    let mut domain_state = canister_state.domain_states.get_mut(&domain).unwrap();
    domain_state.previous_response = Some(res.clone());
    info!("cycle {}", ic_cdk::api::call::msg_cycles_available128());
    Ok(res)
}

#[ic_cdk::update]
pub async fn revoke_dkim_public_key(
    selector: String,
    domain: String,
    private_key_der: String,
) -> Result<SignedRevocation, String> {
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    let accepted_cycles = ic_cdk::api::call::msg_cycles_accept128(available_cycles);
    if available_cycles != accepted_cycles {
        return Err("not all of the available_cycles is moved".to_string());
    }
    info!("available_cycles {}", available_cycles);
    let canister_state = CanisterState::get();
    info!("state {:?}", canister_state.clone());
    let canister_state = canister_state.borrow_mut();
    if available_cycles < canister_state.fee_cycles {
        return Err("not enough cycles".to_string());
    }
    if canister_state.address == "" {
        return Err("ethereum address is not initialized".to_string());
    }
    let revoked_public_key = private_to_public_key(&private_key_der.as_bytes());
    info!("public_key {}", revoked_public_key);
    let fetched_public_key =
        get_dkim_public_key(&selector, &domain, canister_state.http_cycles).await?;
    info!("fetched_public_key {}", fetched_public_key);
    if revoked_public_key != fetched_public_key {
        return Err(
            "The given private key does not correspond to the fetched public key".to_string(),
        );
    }
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
    let (res,): (Result<String, String>,) = ic_cdk::api::call::call_with_payment128(
        poseidon_canister_id,
        "public_key_hash",
        (fetched_public_key.clone(),),
        canister_state.poseidon_cycles,
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
    let message = format!(
        "REVOKE:chain_id={};selector={};domain={};public_key_hash={};",
        canister_state.chain_id, selector, domain, public_key_hash_hex
    );
    let signature = sign(message).await?;

    let res = SignedRevocation {
        selector,
        domain: domain.clone(),
        chain_id: canister_state.chain_id,
        signature,
        public_key: fetched_public_key,
        public_key_hash: public_key_hash_hex,
        private_key: private_key_der,
    };
    // let mut domain_state = canister_state.domain_states.get_mut(&domain).unwrap();
    // domain_state.previous_response = Some(res.clone());
    info!("cycle {}", ic_cdk::api::call::msg_cycles_available128());
    Ok(res)
}

async fn sign(message: String) -> Result<String, String> {
    let signature =
        ic_evm_sign::sign_msg(message.as_bytes().to_vec(), Principal::anonymous()).await?;
    Ok(signature)
}

fn private_to_public_key(private_key_der: &[u8]) -> String {
    let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .expect("Given private key is invalid format.");
    let public_key = private_key.to_public_key();
    if public_key.e() != &BigUint::from(65537u64) {
        panic!("Only the fixed e parameter is supported.");
    }
    "0x".to_string() + &hex::encode(&public_key.n().to_bytes_be())
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use easy_hasher::easy_hasher::raw_keccak256;
    use ethers_core::types::*;
    use hex;
    use poseidon::public_key_hash;
    use rsa::pkcs1::{der::SecretDocument, EncodeRsaPrivateKey};
    use rsa::rand_core::OsRng;

    #[test]
    fn test_sign_dkim_public_key() {
        // The following values are obtained by running the canister locally.
        let selector = "20230601";
        let domain = "gmail.com";
        // let timestamp = 1_697_875_531;
        let public_key = "0x9edbd2293d6192a84a7b4c5c699d31f906e8b83b09b817dbcbf4bcda3c6ca02fd2a1d99f995b360f52801f79a2d40a9d31d535da1d957c44de389920198ab996377df7a009eee7764b238b42696168d1c7ecbc7e31d69bf3fcc337549dc4f0110e070cec0b111021f0435e51db415a2940011aee0d4db4767c32a76308aae634320642d63fe2e018e81f505e13e0765bd8f6366d0b443fa41ea8eb5c5b8aebb07db82fb5e10fe1d265bd61b22b6b13454f6e1273c43c08e0917cd795cc9d25636606145cff02c48d58d0538d96ab50620b28ad9f5aa685b528f41ef1bad24a546c8bdb1707fb6ee7a2e61bbb440cd9ab6795d4c106145000c13aeeedd678b05f";
        let pk_hash = "0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788";
        assert_eq!(public_key_hash(public_key.to_string()).unwrap(), pk_hash);
        let expected_msg = format!(
            "SET:chain_id={};selector={};domain={};public_key_hash={};",
            1, selector, domain, pk_hash
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

    #[test]
    fn test_private_to_public() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let private_key_der = private_key.to_pkcs1_der().unwrap();

        let public_key_hex = private_to_public_key(private_key_der.as_bytes());
        assert_eq!(
            public_key_hex,
            "0x".to_string() + &hex::encode(&public_key.n().to_bytes_be())
        );
    }
}
