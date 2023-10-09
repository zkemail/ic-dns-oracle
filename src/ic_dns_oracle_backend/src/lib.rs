use base64::{engine::general_purpose, Engine as _};
use candid::{CandidType, Principal};
use hex;
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformArgs,
    TransformContext,
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
async fn init(evn_opt: Option<Environment>) {
    ic_evm_sign::init(evn_opt);
}

#[ic_cdk::query]
async fn get_ethereum_address() -> String {
    let canister_state = CANISTER_STATE.with(|s| s.borrow().clone());
    canister_state.address
}

#[ic_cdk::update]
async fn create_ethereum_address() -> Result<String, String> {
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
async fn sign_dkim_public_key(
    chain_id: u64,
    selector: String,
    domain: String,
    tag: String,
) -> Result<SignedDkimPublicKey, String> {
    sign_dkim_public_key_inner(chain_id, selector, domain, tag).await
}

pub(crate) async fn sign_dkim_public_key_inner(
    chain_id: u64,
    selector: String,
    domain: String,
    tag: String,
) -> Result<SignedDkimPublicKey, String> {
    let public_key = get_dkim_public_key(&selector, &domain).await?;
    let message = tag.to_string() + public_key.as_str();
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
