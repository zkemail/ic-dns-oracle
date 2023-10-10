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

#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct SignedDkimPublicKey {
    pub selector: String,
    pub domain: String,
    pub chain_id: u64,
    pub tag: String,
    pub signature: String,
    pub public_key: String,
}

#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct CanisterState {
    pub address: String,
    // pub chain_id: u64,
}

thread_local! {
    pub static CANISTER_STATE: RefCell<CanisterState> = RefCell::new(CanisterState::default());
}

#[ic_cdk::init]
pub async fn init(evn_opt: Option<Environment>) {
    ic_evm_sign::init(evn_opt);
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
    if tag.contains(";") {
        return Err("tag contains ;".to_string());
    }
    let message = format!(
        "selector={};domain={};tag={};public_key={};",
        selector, domain, tag, public_key
    );
    let signature = sign(message, chain_id).await?;
    let res = SignedDkimPublicKey {
        selector,
        domain,
        chain_id,
        tag,
        signature,
        public_key,
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

async fn get_dkim_public_key(selector: &str, domain: &str) -> Result<String, String> {
    let host = "dns.google";
    let url = format!(
        "https://{}/resolve?name={}._domainkey.{}&type=TXT",
        host, selector, domain
    );

    let request_headers = vec![
        HttpHeader {
            name: "Host".to_string(),
            value: format!("{host}:443"),
        },
        HttpHeader {
            name: "User-Agent".to_string(),
            value: "exchange_rate_canister".to_string(),
        },
    ];

    // let context = Context {
    //     bucket_start_time_index: 0,
    //     closing_price_index: 4,
    // };

    // let transform = TransformContext::new(transform, serde_json::to_vec(&context).unwrap());
    //note "CanisterHttpRequestArgument" and "HttpMethod" are declared in line 4
    let request = CanisterHttpRequestArgument {
        url: url.to_string(),
        method: HttpMethod::GET,
        body: None,               //optional for request
        max_response_bytes: None, //optional for request
        transform: None,          //optional for request
        // transform: Some(transform),
        headers: request_headers,
    };

    //Note: in Rust, `http_request()` already sends the cycles needed
    //so no need for explicit Cycles.add() as in Motoko
    match http_request(request, 1_800_000_000).await {
        //4. DECODE AND RETURN THE RESPONSE

        //See:https://docs.rs/ic-cdk/latest/ic_cdk/api/management_canister/http_request/struct.HttpResponse.html
        Ok((response,)) => {
            if response.status != 200 {
                // ic_cdk::api::print(format!("Received an error from coinbase: err = {:?}", raw));
                return Err(format!(
                    "Received an error from coinbase: err = {:?}",
                    response.body
                ));
            }
            let body_json = serde_json::from_slice::<Value>(&response.body).unwrap();
            let data = body_json["Answer"][0]["data"].to_string();
            let v = Regex::new("v=[A-Z0-9]+")
                .unwrap()
                .find(&data)
                .expect("v= part does not exist")
                .as_str();
            if v != "v=DKIM1" {
                return Err("Error: DKIM version is not DKIM1".to_string());
            }
            let k = Regex::new("k=[a-z]+")
                .unwrap()
                .find(&data)
                .unwrap()
                .as_str();
            if k != "k=rsa" {
                return Err("Error: DKIM record is not RSA key".to_string());
            }
            let pubkey_base64 = Regex::new("p=[A-Za-z0-9\\+/]+")
                .unwrap()
                .find(&data)
                .unwrap()
                .as_str();
            let pubkey_pkcs = general_purpose::STANDARD
                .decode(&pubkey_base64.to_string()[2..])
                .expect("base64 decode failed");
            let pubkey_bytes = RsaPublicKey::from_public_key_der(&pubkey_pkcs)
                .map_err(|_| RsaPublicKey::from_pkcs1_der(&pubkey_pkcs))
                .expect("Invalid DER-encoded rsa public key.");
            let pubkey_hex = "0x".to_string() + &hex::encode(&pubkey_bytes.n().to_bytes_be());
            // let str_body = String::from_utf8(response.body)
            //     .expect("Transformed response is not UTF-8 encoded.");
            Ok(pubkey_hex)
        }
        Err((r, m)) => {
            let message =
                format!("The http_request resulted into error. RejectionCode: {r:?}, Error: {m}");

            //Return the error as a string and end the method
            Err(message)
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use easy_hasher::easy_hasher::raw_keccak256;
    use ethers_core::types::*;

    #[test]
    fn test_sign_dkim_public_key() {
        // The following values are obtained by running the canister locally.
        let selector = "20230601";
        let domain = "gmail.com";
        let tag = "test";
        let public_key = "0x9edbd2293d6192a84a7b4c5c699d31f906e8b83b09b817dbcbf4bcda3c6ca02fd2a1d99f995b360f52801f79a2d40a9d31d535da1d957c44de389920198ab996377df7a009eee7764b238b42696168d1c7ecbc7e31d69bf3fcc337549dc4f0110e070cec0b111021f0435e51db415a2940011aee0d4db4767c32a76308aae634320642d63fe2e018e81f505e13e0765bd8f6366d0b443fa41ea8eb5c5b8aebb07db82fb5e10fe1d265bd61b22b6b13454f6e1273c43c08e0917cd795cc9d25636606145cff02c48d58d0538d96ab50620b28ad9f5aa685b528f41ef1bad24a546c8bdb1707fb6ee7a2e61bbb440cd9ab6795d4c106145000c13aeeedd678b05f";
        let expected_msg = format!(
            "selector={};domain={};tag={};public_key={};",
            selector, domain, tag, public_key
        );
        let signature = Signature::from_str("0x1f2dd623b8efb8fd9200a4550ebab8a4e45e17d10fbe5dbf9e15d193f26201d958a062d8682033226030000d740cf3534ae2ed8327401141a188231d81a6202125").unwrap();
        let recovered = signature.recover(expected_msg).unwrap();
        assert_eq!(
            recovered,
            H160::from_slice(&hex::decode("b11348be7f856fbf0f6b924cc969272cf4684cdf").unwrap())
        );
    }
}
