use base64::{engine::general_purpose, Engine as _};
use candid::{Nat, Principal};
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformArgs,
    TransformContext,
};
use regex::Regex;
use rsa::{
    pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey,
};
use serde_json::{self, Value};

#[ic_cdk::update]
pub async fn get_dkim_public_key(
    selector: String,
    domain: String,
    cycle: u64,
) -> Result<String, String> {
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

    let transform = TransformContext::from_name("transform".to_string(), vec![]);
    //note "CanisterHttpRequestArgument" and "HttpMethod" are declared in line 4
    let request = CanisterHttpRequestArgument {
        url: url.to_string(),
        method: HttpMethod::GET,
        body: None,               //optional for request
        max_response_bytes: None, //optional for request
        // transform: None,          //optional for request
        transform: Some(transform),
        headers: request_headers,
    };

    //Note: in Rust, `http_request()` already sends the cycles needed
    //so no need for explicit Cycles.add() as in Motoko
    match http_request(request, cycle as u128).await {
        //4. DECODE AND RETURN THE RESPONSE

        //See:https://docs.rs/ic-cdk/latest/ic_cdk/api/management_canister/http_request/struct.HttpResponse.html
        Ok((response,)) => {
            if response.status != Nat::from(200u64) {
                // ic_cdk::api::print(format!("Received an error from coinbase: err = {:?}", raw));
                return Err(format!(
                    "Received an error from google dns: err = {:?}",
                    response.body
                ));
            }
            let pubkey_hex = "0x".to_string() + &hex::encode(&response.body);
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

#[ic_cdk::query]
fn transform(raw: TransformArgs) -> HttpResponse {
    let headers = vec![
        HttpHeader {
            name: "Content-Security-Policy".to_string(),
            value: "default-src 'self'".to_string(),
        },
        HttpHeader {
            name: "Referrer-Policy".to_string(),
            value: "strict-origin".to_string(),
        },
        HttpHeader {
            name: "Permissions-Policy".to_string(),
            value: "geolocation=(self)".to_string(),
        },
        HttpHeader {
            name: "Strict-Transport-Security".to_string(),
            value: "max-age=63072000".to_string(),
        },
        HttpHeader {
            name: "X-Frame-Options".to_string(),
            value: "DENY".to_string(),
        },
        HttpHeader {
            name: "X-Content-Type-Options".to_string(),
            value: "nosniff".to_string(),
        },
    ];

    if raw.response.status != Nat::from(200u64) {
        return HttpResponse {
            status: raw.response.status.clone(),
            body: b"error status".to_vec(),
            headers,
            ..Default::default()
        };
    }
    let body_json = serde_json::from_slice::<Value>(&raw.response.body).unwrap();
    let answers: Vec<Value> = body_json["Answer"]
        .as_array()
        .expect("No array of Answer")
        .to_vec();
    for i in 0..answers.len() {
        let data = answers[i]["data"].to_string();
        let k = Regex::new("k=[a-z]+").unwrap().find(&data);
        match k {
            None => continue,
            Some(k) => {
                if k.as_str() != "k=rsa" {
                    continue;
                }
            }
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

        return HttpResponse {
            status: raw.response.status.clone(),
            body: pubkey_bytes.n().to_bytes_be(),
            headers,
            ..Default::default()
        };
    }
    HttpResponse {
        status: Nat::from(400u64),
        body: b"No key found".to_vec(),
        headers,
        ..Default::default()
    }
}
