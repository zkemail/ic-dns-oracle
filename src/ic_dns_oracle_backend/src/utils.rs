use base64::{engine::general_purpose, Engine as _};
use candid::Principal;
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod,
};
use regex::Regex;
use rsa::{
    pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey,
};
use serde_json::{self, Value};

pub(crate) async fn create_ethereum_address() -> Result<String, String> {
    let res = ic_evm_sign::create_address(Principal::anonymous())
        .await
        .expect("create_address failed");
    Ok(res.address)
}

pub(crate) async fn get_dkim_public_key(selector: &str, domain: &str) -> Result<String, String> {
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
