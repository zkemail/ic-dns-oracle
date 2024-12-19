use std::collections::HashMap;

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

const SELECTOR_REGEX: &str =
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$";
const DOMAIN_REGEX: &str =
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$";
// consumed cycle for get_dkim_public_key: 745_646_986 cycles
// the consumed cycle * 1.479 is charged cycle = 1_102_987_035 cycles
pub const CHARGED_CYCLE: u128 = 1_102_987_035;

/// Fetches the DKIM public key for the given selector and domain.
///
/// # Arguments
///
/// * `selector` - The DKIM selector.
/// * `domain` - The domain for which to fetch the DKIM public key.
/// * `cycle` - The number of cycles to send with the request.
///
/// # Returns
///
/// A result containing the DKIM public key as a hexadecimal string, or an error message.
#[ic_cdk::update]
pub async fn get_dkim_public_key(
    selector: String,
    domain: String,
    cycle: u64,
) -> Result<String, String> {
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    #[cfg(not(debug_assertions))]
    {
        if available_cycles < CHARGED_CYCLE {
            return Err("Insufficient cycles".to_string());
        }
    }
    let accepted_cycles = ic_cdk::api::call::msg_cycles_accept128(CHARGED_CYCLE);
    if available_cycles != accepted_cycles {
        return Err("Fail to accept all available cycles".to_string());
    }
    // Verify selector and domain
    if !Regex::new(SELECTOR_REGEX).unwrap().is_match(&selector) {
        return Err("Invalid domain".to_string());
    }
    if !Regex::new(DOMAIN_REGEX).unwrap().is_match(&domain) {
        return Err("Invalid selector".to_string());
    }

    // #[cfg(not(debug_assertions))]
    let prefixes = vec![
        "https://dns.google/resolve",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.nextdns.io/dns-query",
    ];

    // #[cfg(debug_assertions)]
    // let prefixes = vec!["https://dns.google/resolve"];
    // let (seed_raw,): ([u8; 32],) = ic_cdk::call(Principal::management_canister(), "raw_rand", ())
    //     .await
    //     .expect("Failed to call the management canister");
    // let seed = (seed_raw[0..16].iter().map(|&b| b as u128).sum::<u128>() % 3) as usize;

    let seed = ic_cdk::api::time() as usize % prefixes.len();
    let mut shuffled_prefixes = vec![];
    for i in 0..prefixes.len() {
        shuffled_prefixes.push(prefixes[(seed + i) % prefixes.len()]);
    }

    let mut logs = vec![];
    let mut pubkey_votes = vec![];
    for prefix in shuffled_prefixes {
        let request = _construct_request(prefix, &selector, &domain);
        match http_request(request, cycle as u128).await {
            // Decode and return the response.
            Ok((response,)) => {
                if response.status != Nat::from(200u64) {
                    let message = format!(
                        "[Access to {prefix}] The response status is {}.",
                        response.status
                    );
                    logs.push(message);
                    continue;
                }
                let pubkey_hex = "0x".to_string() + &hex::encode(&response.body);
                // if the same pubkey is voted by two different dns resolvers, the same pubkey should be contained in pubkey_votes.
                if pubkey_votes.contains(&pubkey_hex) {
                    return Ok(pubkey_hex);
                } else {
                    pubkey_votes.push(pubkey_hex);
                }
                let message: String = format!(
                    "[Access to {prefix}] The response status is {}.",
                    response.status
                );
                logs.push(message);
                continue;
            }
            Err((r, m)) => {
                let message = format!(
                    "[Access to {prefix}] The http_request resulted into error. RejectionCode: {r:?}, Error: {m}."
                );
                logs.push(message);
                continue;
            }
        }
    }
    // Return the error as a string and end the method.
    return Err(logs.join("\n"));
}

/// Transforms the raw HTTP response into a structured `HttpResponse`.
///
/// # Arguments
///
/// * `raw` - The raw HTTP response to transform.
///
/// # Returns
///
/// A structured `HttpResponse`.
#[ic_cdk::query]
fn transform(raw: TransformArgs) -> HttpResponse {
    match _transform(raw) {
        Ok(res) => res,
        Err(e) => HttpResponse {
            status: Nat::from(500u64),
            body: e.as_bytes().to_vec(),
            headers: vec![],
            ..Default::default()
        },
    }
}

/// Helper function to construct the HTTP request.
/// # Arguments
/// * `prefix` - The prefix of the DNS resolver.
/// * `selector` - The DKIM selector.
/// * `domain` - The domain for which to fetch the DKIM public key.
/// # Returns
/// A structured `CanisterHttpRequestArgument`.
fn _construct_request(prefix: &str, selector: &str, domain: &str) -> CanisterHttpRequestArgument {
    let url = format!(
        "{}?name={}._domainkey.{}&type=TXT",
        prefix, selector, domain
    );

    let request_headers = vec![HttpHeader {
        name: "Accept".to_string(),
        value: "application/dns-json".to_string(),
    }];

    let expected_name = format!("\"{}._domainkey.{}.\"", selector, domain);
    let transform =
        TransformContext::from_name("transform".to_string(), expected_name.as_bytes().to_vec());
    CanisterHttpRequestArgument {
        url: url.to_string(),
        method: HttpMethod::GET,
        body: None,                      // Optional for request
        max_response_bytes: Some(65536), // 64KB
        transform: Some(transform),
        headers: request_headers,
    }
}

/// Helper function to transform the raw HTTP response.
///
/// # Arguments
///
/// * `raw` - The raw HTTP response to transform.
///
/// # Returns
///
/// A result containing the structured `HttpResponse`, or an error message.
fn _transform(raw: TransformArgs) -> Result<HttpResponse, String> {
    if raw.response.status != Nat::from(200u64) {
        return Err(format!(
            "Received an error with code {} from the dns service: err = {:?}",
            raw.response.status, raw.response.body
        ));
    }
    let body_json = serde_json::from_slice::<Value>(&raw.response.body).unwrap();
    let answers: Vec<Value> = body_json["Answer"]
        .as_array()
        .ok_or_else(|| "No array of Answer")?
        .to_vec();
    let expected_name = String::from_utf8(raw.context).expect("context is not a valid utf8 string");
    for i in 0..answers.len() {
        if let Some(name) = answers[i].get("name") {
            if name.to_string() != expected_name {
                continue;
            }
        }
        if let Some(dns_type) = answers[i].get("type") {
            if dns_type.to_string() != "16" {
                continue;
            }
        }
        let data = answers[i]["data"].to_string();
        if let Some(k_caps) = Regex::new("k=([a-z]+)").unwrap().captures(&data) {
            if &k_caps[1] != "rsa" {
                continue;
            }
        }

        if let Some(v_caps) = Regex::new("v=([A-Z0-9]+)").unwrap().captures(&data) {
            if &v_caps[1] != "DKIM1" {
                continue;
            }
        }

        if let Some(p_caps) = Regex::new(r#"p=([A-Za-z0-9\\+/" ]+);?"#)
            .unwrap()
            .captures(&data)
        {
            let remove_regex = Regex::new(r#"["\\ ]"#).unwrap();
            let pubkey_base64 = p_caps.get(1).unwrap().as_str();
            let pubkey_base64 = remove_regex.replace_all(pubkey_base64, "").to_string();
            let pubkey_pkcs = general_purpose::STANDARD
                .decode(&pubkey_base64)
                .map_err(|e| {
                    format!(
                        "base64 decode of {} failed: {}",
                        pubkey_base64,
                        e.to_string()
                    )
                })?;
            let pubkey_bytes = match RsaPublicKey::from_public_key_der(&pubkey_pkcs) {
                Ok(pubkey) => pubkey,
                Err(_) => RsaPublicKey::from_pkcs1_der(&pubkey_pkcs)
                    .map_err(|e| format!("Invalid encoded rsa public key: {}", e.to_string()))?,
            };
            return Ok(HttpResponse {
                status: raw.response.status.clone(),
                body: pubkey_bytes.n().to_bytes_be().to_vec(),
                headers: vec![],
                ..Default::default()
            });
        }
    }
    Err("No key found".to_string())
}

ic_cdk::export_candid!();

#[cfg(test)]
mod test {
    use candid::{decode_one, Encode, Principal};
    use pocket_ic::{
        common::rest::{CanisterHttpReply, CanisterHttpResponse, MockCanisterHttpResponse},
        PocketIc, PocketIcBuilder, WasmResult,
    };

    #[test]
    fn test_dns_client_gmail_two_responses() {
        let (pic, canister_id) = test_setup();
        // Submit an update call to the test canister making a canister http outcall
        // and mock a canister http outcall response.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "get_dkim_public_key",
                Encode!(&"20230601", &"gmail.com", &1_000_000_000_000u64).unwrap(),
            )
            .unwrap();

        let body = r#"
            {
                "Status": 0,
                "TC": false,
                "RD": true,
                "RA": true,
                "AD": false,
                "CD": false,
                "Question": [
                    {
                        "name": "20230601._domainkey.gmail.com.",
                        "type": 16
                    }
                ],
                "Answer": [
                    {
                        "name": "20230601._domainkey.gmail.com.",
                        "type": 16,
                        "TTL": 3600,
                        "data": "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KAH3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mdab8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBkLWP+LgGOgfUF4T4HZb2PY2bQtEP6QeqOtcW4rrsH24L7XhD+HSZb1hsitrE0VPbhJzxDwI4JF815XMnSVjZgYUXP8CxI1Y0FONlqtQYgsorZ9apoW1KPQe8brSSlRsi9sXB/tu56LmG7tEDNmrZ5XUwQYUUADBOu7t1niwXwIDAQAB"
                    }
                ],
                "Comment": "Response from 216.239.32.10."
            }
            "#;
        mock_http_response(&pic, body);
        pic.tick();
        mock_http_response(&pic, body);

        // Now the test canister will receive the http outcall response
        // and reply to the ingress message from the test driver.
        let reply = pic.await_call(call_id).unwrap();
        match reply {
            WasmResult::Reply(data) => {
                let http_response: Result<String, String> = decode_one(&data).unwrap();
                assert_eq!(http_response.unwrap(), "0x9edbd2293d6192a84a7b4c5c699d31f906e8b83b09b817dbcbf4bcda3c6ca02fd2a1d99f995b360f52801f79a2d40a9d31d535da1d957c44de389920198ab996377df7a009eee7764b238b42696168d1c7ecbc7e31d69bf3fcc337549dc4f0110e070cec0b111021f0435e51db415a2940011aee0d4db4767c32a76308aae634320642d63fe2e018e81f505e13e0765bd8f6366d0b443fa41ea8eb5c5b8aebb07db82fb5e10fe1d265bd61b22b6b13454f6e1273c43c08e0917cd795cc9d25636606145cff02c48d58d0538d96ab50620b28ad9f5aa685b528f41ef1bad24a546c8bdb1707fb6ee7a2e61bbb440cd9ab6795d4c106145000c13aeeedd678b05f");
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
        // There should be no more pending canister http outcalls.
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
    }

    #[test]
    fn test_dns_client_gmail_single_answer() {
        let (pic, canister_id) = test_setup();
        // Submit an update call to the test canister making a canister http outcall
        // and mock a canister http outcall response.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "get_dkim_public_key",
                Encode!(&"20230601", &"gmail.com", &1_000_000_000_000u64).unwrap(),
            )
            .unwrap();

        let body = r#"
            {
                "Status": 0,
                "TC": false,
                "RD": true,
                "RA": true,
                "AD": false,
                "CD": false,
                "Question": [
                    {
                        "name": "20230601._domainkey.gmail.com.",
                        "type": 16
                    }
                ],
                "Answer": [
                    {
                        "name": "20230601._domainkey.gmail.com.",
                        "type": 16,
                        "TTL": 3600,
                        "data": "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KAH3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mdab8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBkLWP+LgGOgfUF4T4HZb2PY2bQtEP6QeqOtcW4rrsH24L7XhD+HSZb1hsitrE0VPbhJzxDwI4JF815XMnSVjZgYUXP8CxI1Y0FONlqtQYgsorZ9apoW1KPQe8brSSlRsi9sXB/tu56LmG7tEDNmrZ5XUwQYUUADBOu7t1niwXwIDAQAB"
                    }
                ],
                "Comment": "Response from 216.239.32.10."
            }
            "#;
        mock_http_response(&pic, body);
        pic.tick();
        let body = r#"
        {
            "Status": 0,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": false,
            "CD": false,
            "Question": [
                {
                    "name": "20230601._domainkey.gmail.com.",
                    "type": 16
                }
            ],
            "Comment": "Response from 216.239.32.10."
        }
        "#;
        mock_http_response(&pic, body);
        pic.tick();
        let body = r#"
        {
            "Status": 0,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": false,
            "CD": false,
            "Question": [
                {
                    "name": "20230601._domainkey.gmail.com.",
                    "type": 16
                }
            ],
            "Comment": "Response from 216.239.32.10."
        }
        "#;
        mock_http_response(&pic, body);
        // Now the test canister will receive the http outcall response
        // and reply to the ingress message from the test driver.
        let reply = pic.await_call(call_id).unwrap();
        match reply {
            WasmResult::Reply(data) => {
                let http_response: Result<String, String> = decode_one(&data).unwrap();
                assert!(http_response.is_err());
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
        // There should be no more pending canister http outcalls.
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
    }

    #[test]
    fn test_dns_client_expect_error_no_answer() {
        let (pic, canister_id) = test_setup();
        // Submit an update call to the test canister making a canister http outcall
        // and mock a canister http outcall response.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "get_dkim_public_key",
                Encode!(&"20230601", &"gmail.com", &1_000_000_000_000u64).unwrap(),
            )
            .unwrap();

        let body = r#"
            {
                "Status": 0,
                "TC": false,
                "RD": true,
                "RA": true,
                "AD": false,
                "CD": false,
                "Question": [
                    {
                        "name": "20230601._domainkey.gmail.com.",
                        "type": 16
                    }
                ],
                "Comment": "Response from 216.239.32.10."
            }
            "#;
        mock_http_response(&pic, body);
        pic.tick();
        mock_http_response(&pic, body);
        pic.tick();
        mock_http_response(&pic, body);

        // Now the test canister will receive the http outcall response
        // and reply to the ingress message from the test driver.
        let reply = pic.await_call(call_id).unwrap();
        match reply {
            WasmResult::Reply(data) => {
                let http_response: Result<String, String> = decode_one(&data).unwrap();
                assert!(http_response.is_err());
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
        // There should be no more pending canister http outcalls.
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
    }

    #[test]
    fn test_dns_client_expect_error_invalid_key_type() {
        let (pic, canister_id) = test_setup();
        // Submit an update call to the test canister making a canister http outcall
        // and mock a canister http outcall response.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "get_dkim_public_key",
                Encode!(&"20230601", &"gmail.com", &1_000_000_000_000u64).unwrap(),
            )
            .unwrap();

        let body = r#"
            {
                "Status": 0,
                "TC": false,
                "RD": true,
                "RA": true,
                "AD": false,
                "CD": false,
                "Question": [
                    {
                        "name": "20230601._domainkey.gmail.com.",
                        "type": 16
                    }
                ],
                "Answer": [
                    {
                        "name": "20230601._domainkey.gmail.com.",
                        "type": 16,
                        "TTL": 3600,
                        "data": "v=DKIM1; k=eddsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KAH3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mdab8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBkLWP+LgGOgfUF4T4HZb2PY2bQtEP6QeqOtcW4rrsH24L7XhD+HSZb1hsitrE0VPbhJzxDwI4JF815XMnSVjZgYUXP8CxI1Y0FONlqtQYgsorZ9apoW1KPQe8brSSlRsi9sXB/tu56LmG7tEDNmrZ5XUwQYUUADBOu7t1niwXwIDAQAB"
                    }
                ],
                "Comment": "Response from 216.239.32.10."
            }
            "#;
        mock_http_response(&pic, body);
        pic.tick();
        mock_http_response(&pic, body);
        pic.tick();
        mock_http_response(&pic, body);

        // Now the test canister will receive the http outcall response
        // and reply to the ingress message from the test driver.
        let reply = pic.await_call(call_id).unwrap();
        match reply {
            WasmResult::Reply(data) => {
                let http_response: Result<String, String> = decode_one(&data).unwrap();
                assert!(http_response.is_err());
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
        // There should be no more pending canister http outcalls.
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
    }

    #[test]
    fn test_dns_client_expect_error_invalid_base64_format() {
        let (pic, canister_id) = test_setup();

        // Submit an update call to the test canister making a canister http outcall
        // and mock a canister http outcall response.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "get_dkim_public_key",
                Encode!(&"20230601", &"gmail.com", &1_000_000_000_000u64).unwrap(),
            )
            .unwrap();

        let body = r#"
            {
                "Status": 0,
                "TC": false,
                "RD": true,
                "RA": true,
                "AD": false,
                "CD": false,
                "Question": [
                    {
                        "name": "20230601._domainkey.gmail.com.",
                        "type": 16
                    }
                ],
                "Answer": [
                    {
                        "name": "20230601._domainkey.gmail.com.",
                        "type": 16,
                        "TTL": 3600,
                        "data": "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KAH3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mdab8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBkLWP+LgGOgfUF4T4HZb2PY2bQtEP6QeqOtcW4rrsH24L7XhD+HSZb1hsitrE0VPbhJzxDwI4JF815XMnSVjZgYUXP8CxI1Y0FONlqtQYgsorZ9apoW1KPQe8brSSlRsi9sXB/tu56LmG7tEDNmrZ5XUwQYUUADBOu7t1niwXwIDAQ!"
                    }
                ],
                "Comment": "Response from 216.239.32.10."
            }
            "#;
        mock_http_response(&pic, body);
        pic.tick();
        mock_http_response(&pic, body);
        pic.tick();
        mock_http_response(&pic, body);

        // Now the test canister will receive the http outcall response
        // and reply to the ingress message from the test driver.
        let reply = pic.await_call(call_id).unwrap();
        match reply {
            WasmResult::Reply(data) => {
                let http_response: Result<String, String> = decode_one(&data).unwrap();
                assert!(http_response.is_err());
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
        // There should be no more pending canister http outcalls.
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
    }

    #[test]
    fn test_dns_client_expect_error_invalid_selector() {
        let (pic, canister_id) = test_setup();

        // Submit an update call to the test canister making a canister http outcall
        // and mock a canister http outcall response.
        let selector = "20230601._domainkey.gmail.com&name=xx";
        let domain = "any.com";
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "get_dkim_public_key",
                Encode!(&selector, &domain, &1_000_000_000_000u64).unwrap(),
            )
            .unwrap();
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
        // Now the test canister will receive the http outcall response
        // and reply to the ingress message from the test driver.
        let reply = pic.await_call(call_id).unwrap();
        match reply {
            WasmResult::Reply(data) => {
                let http_response: Result<String, String> = decode_one(&data).unwrap();
                assert!(http_response.is_err());
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
        // There should be no more pending canister http outcalls.
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
    }

    #[test]
    fn test_dns_client_expect_error_invalid_domain() {
        let (pic, canister_id) = test_setup();

        // Submit an update call to the test canister making a canister http outcall
        // and mock a canister http outcall response.
        let selector = "20230601";
        let domain = ".gmail.com";
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "get_dkim_public_key",
                Encode!(&selector, &domain, &1_000_000_000_000u64).unwrap(),
            )
            .unwrap();
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
        // Now the test canister will receive the http outcall response
        // and reply to the ingress message from the test driver.
        let reply = pic.await_call(call_id).unwrap();
        match reply {
            WasmResult::Reply(data) => {
                let http_response: Result<String, String> = decode_one(&data).unwrap();
                assert!(http_response.is_err());
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
        // There should be no more pending canister http outcalls.
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
    }

    fn test_setup() -> (PocketIc, Principal) {
        let pic = PocketIcBuilder::new()
            .with_nns_subnet()
            .with_ii_subnet() // this subnet has ECDSA keys
            .with_application_subnet()
            .build();

        let topology = pic.topology();
        let app_subnet = topology.get_app_subnets()[0];

        // Create an empty canister as the anonymous principal and add cycles.
        let canister_id = pic.create_canister_on_subnet(None, None, app_subnet);
        pic.add_cycles(canister_id, 2_000_000_000_000);
        let wasm_bytes =
            include_bytes!("../../../target/wasm32-unknown-unknown/debug/dns_client.wasm").to_vec();
        pic.install_canister(canister_id, wasm_bytes, vec![], None);
        (pic, canister_id)
    }

    fn mock_http_response(pic: &PocketIc, body: &str) {
        // We need a pair of ticks for the test canister method to make the http outcall
        // and for the management canister to start processing the http outcall.
        pic.tick();
        pic.tick();
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 1);
        let canister_http_request = &canister_http_requests[0];
        let mock_canister_http_response = MockCanisterHttpResponse {
            subnet_id: canister_http_request.subnet_id,
            request_id: canister_http_request.request_id,
            response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                status: 200,
                headers: vec![],
                body: body.as_bytes().to_vec(),
            }),
            additional_responses: vec![],
        };
        pic.mock_canister_http_response(mock_canister_http_response);
    }
}
