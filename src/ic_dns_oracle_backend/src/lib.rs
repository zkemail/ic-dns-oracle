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
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableLog};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    pkcs8::DecodePublicKey,
    traits::{PrivateKeyParts, PublicKeyParts},
    BigUint, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, cell::RefCell, collections::HashMap};

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

type Memory = VirtualMemory<DefaultMemoryImpl>;
thread_local! {
    // The memory manager is used for simulating multiple memories. Given a `MemoryId` it can
    // return a memory that can be used by stable structures.
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    // Initialize a `StableBTreeMap` with `MemoryId(0)`.
    static CONFIG: RefCell<StableBTreeMap<u128, String, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    // Initialize a `StableLog` with `MemoryId(1)` and `MemoryId(2)`.
    static LOG: RefCell<StableLog<String, Memory, Memory>> = RefCell::new(
        StableLog::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
        ).expect("failed to init Log")
    );
}

#[ic_cdk::init]
pub fn init(
    evn_opt: Option<Environment>,
    poseidon_canister_id: String,
    dns_client_canister_id: String,
) {
    ic_evm_sign::init(evn_opt.clone());
    CONFIG.with(|config| {
        config.borrow_mut().insert(1, poseidon_canister_id.clone());
        config
            .borrow_mut()
            .insert(2, dns_client_canister_id.clone());
    });
}

#[ic_cdk::pre_upgrade]
pub fn pre_upgrade_function() {
    ic_evm_sign::pre_upgrade();
}

#[ic_cdk::post_upgrade]
pub fn post_upgrade_function(poseidon_canister_id: String, dns_client_canister_id: String) {
    ic_evm_sign::post_upgrade();
    CONFIG.with(|config| {
        config.borrow_mut().insert(1, poseidon_canister_id.clone());
        config
            .borrow_mut()
            .insert(2, dns_client_canister_id.clone());
    });
}

#[ic_cdk::query]
pub fn get_ethereum_address() -> String {
    CONFIG.with(|config| {
        config
            .borrow()
            .get(&0)
            .expect("eth address not found")
            .clone()
    })
}

#[ic_cdk::query]
pub fn get_poseidon_canister_id() -> String {
    CONFIG.with(|config| {
        config
            .borrow()
            .get(&1)
            .expect("poseidon_canister not found")
            .clone()
    })
}

#[ic_cdk::query]
pub fn get_dns_client_canister_id() -> String {
    CONFIG.with(|config| {
        config
            .borrow()
            .get(&2)
            .expect("dns_client_canister not found")
            .clone()
    })
}

#[ic_cdk::query]
pub fn read_log_from_first(num_log: u64) -> Result<Vec<String>, String> {
    let mut logs = Vec::with_capacity(num_log as usize);
    let log_len = LOG.with(|log| log.borrow().len());
    if num_log > log_len {
        return Err(format!(
            "num_log {} is greater than log length {}",
            num_log, log_len
        ));
    }
    for idx in 0..num_log {
        LOG.with(|log| {
            let mut buf = Vec::new();
            log.borrow()
                .read_entry(idx, &mut buf)
                .expect("failed to read log");
            logs.push(String::from_utf8(buf).unwrap());
        });
    }
    Ok(logs)
}

#[ic_cdk::query]
pub fn read_log_from_last(num_log: u64) -> Result<Vec<String>, String> {
    let mut logs = Vec::with_capacity(num_log as usize);
    let log_len = LOG.with(|log| log.borrow().len());
    if num_log > log_len {
        return Err(format!(
            "num_log {} is greater than log length {}",
            num_log, log_len
        ));
    }
    for idx in (log_len - num_log)..log_len {
        LOG.with(|log| {
            let mut buf = Vec::new();
            log.borrow()
                .read_entry(log_len - idx - 1, &mut buf)
                .expect("failed to read log");
            logs.push(String::from_utf8(buf).unwrap());
        });
    }
    Ok(logs)
}

#[ic_cdk::update]
pub async fn sign_dkim_public_key(
    selector: String,
    domain: String,
) -> Result<SignedDkimPublicKey, String> {
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn sign_dkim_public_key: [input] selector {}, domain {}",
                selector, domain
            ))
            .expect("failed to append log");
    });
    let domain_with_gappssmtp =
        format!("{}.{}.gappssmtp.com", &domain.replace(".", "-"), &selector);
    let mut error0 = String::new();
    match _sign_dkim_public_key(selector.clone(), domain).await {
        Ok(res) => {
            LOG.with(|log| {
                log.borrow_mut()
                    .append(&format!(
                        "fn sign_dkim_public_key: [first try output] {:?}",
                        res
                    ))
                    .expect("failed to append log");
            });
            return Ok(res);
        }
        Err(e) => {
            error0 = e;
        }
    }
    let mut error1 = String::new();
    match _sign_dkim_public_key(selector, domain_with_gappssmtp).await {
        Ok(res) => {
            LOG.with(|log| {
                log.borrow_mut()
                    .append(&format!(
                        "fn sign_dkim_public_key: [first try error] {}, [second try output] {:?}",
                        error0, res
                    ))
                    .expect("failed to append log");
            });
            return Ok(res);
        }
        Err(e) => {
            error1 = e;
        }
    }
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn sign_dkim_public_key: [first try error] {}, [second try error] {}",
                error0, error1
            ))
            .expect("failed to append log");
    });
    Err(format!(
        "any signing failed. error0: {}, error1: {}",
        error0, error1
    ))
}

#[ic_cdk::update]
async fn _sign_dkim_public_key(
    selector: String,
    domain: String,
) -> Result<SignedDkimPublicKey, String> {
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    ic_cdk::api::call::msg_cycles_accept128(available_cycles);
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _sign_dkim_public_key: [available cycles] {}",
                available_cycles
            ))
            .expect("failed to append log");
    });
    let is_null_addr = CONFIG.with(|config| config.borrow().get(&0).is_none());
    if is_null_addr {
        let address = create_ethereum_address().await?;
        CONFIG.with(|config| {
            config.borrow_mut().insert(0, address.clone());
        });
        LOG.with(|log| {
            log.borrow_mut()
                .append(&format!(
                    "fn _sign_dkim_public_key: [generated ethereum address] {}",
                    address
                ))
                .expect("failed to append log");
        });
    }
    let dns_client_canister_id_str = CONFIG.with(|config| {
        config
            .borrow()
            .get(&2)
            .expect("dns_client_canister not found")
            .clone()
    });
    let dns_client_canister_id = Principal::from_text(dns_client_canister_id_str).unwrap();
    let (public_key,): (Result<String, String>,) = ic_cdk::api::call::call(
        dns_client_canister_id,
        "get_dkim_public_key",
        (&selector, &domain, 40_000_000_000u64),
    )
    .await
    .map_err(|(code, e)| format!("dns_client canister error. {:?}, {}", code, e))?;
    let public_key = public_key?;
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _sign_dkim_public_key: [fetched public key] {}",
                public_key
            ))
            .expect("failed to append log");
    });
    let poseidon_canister_id_str = CONFIG.with(|config| {
        config
            .borrow()
            .get(&1)
            .expect("poseidon_canister not found")
            .clone()
    });
    let poseidon_canister_id = Principal::from_text(poseidon_canister_id_str).unwrap();
    let (res,): (Result<String, String>,) = ic_cdk::api::call::call(
        poseidon_canister_id,
        "public_key_hash",
        (public_key.clone(),),
    )
    .await
    .map_err(|(code, e)| format!("poseidon canister error. {:?}, {}", code, e))?;
    let public_key_hash_hex = res?;
    let message = format!(
        "SET:domain={};public_key_hash={};",
        domain, public_key_hash_hex
    );
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _sign_dkim_public_key: [signed message] {}",
                message
            ))
            .expect("failed to append log");
    });
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
) -> Result<SignedRevocation, String> {
    let mut error0 = String::new();
    match _revoke_dkim_public_key(selector.clone(), domain.clone(), private_key_der.clone()).await {
        Ok(res) => {
            LOG.with(|log| {
                log.borrow_mut()
                    .append(&format!(
                        "fn revoke_dkim_public_key: [first try output] {:?}",
                        res
                    ))
                    .expect("failed to append log");
            });
            return Ok(res);
        }
        Err(e) => {
            error0 = e;
        }
    }
    let domain_with_gappssmtp =
        format!("{}.{}.gappssmtp.com", &domain.replace(".", "-"), &selector);
    let mut error1 = String::new();
    match _revoke_dkim_public_key(selector, domain_with_gappssmtp, private_key_der).await {
        Ok(res) => {
            LOG.with(|log| {
                log.borrow_mut()
                    .append(&format!(
                        "fn revoke_dkim_public_key: [first try error] {}, [second try output] {:?}",
                        error0, res
                    ))
                    .expect("failed to append log");
            });
            return Ok(res);
        }
        Err(e) => {
            error1 = e;
        }
    }
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn revoke_dkim_public_key: [first try error] {}, [second try error] {}",
                error0, error1
            ))
            .expect("failed to append log");
    });
    Err(format!(
        "any revocation failed. error0: {}, error1: {}",
        error0, error1
    ))
}

async fn _revoke_dkim_public_key(
    selector: String,
    domain: String,
    private_key_der: String,
) -> Result<SignedRevocation, String> {
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    ic_cdk::api::call::msg_cycles_accept128(available_cycles);
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _revoke_dkim_public_key: [available cycles] {}",
                available_cycles
            ))
            .expect("failed to append log");
    });
    if CONFIG.with(|config| config.borrow().get(&0).is_none()) {
        return Err("ethereum address not found".to_string());
    }
    let revoked_public_key = {
        let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der.as_bytes())
            .expect("Invalid format private key");
        let public_key = private_key.to_public_key();
        assert!(public_key.e() == &BigUint::from(65537u64));
        "0x".to_string() + &hex::encode(&public_key.n().to_bytes_be())
    };
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _revoke_dkim_public_key: [revoked public key] {}",
                revoked_public_key
            ))
            .expect("failed to append log");
    });
    let dns_client_canister_id_str = CONFIG.with(|config| {
        config
            .borrow()
            .get(&2)
            .expect("dns_client_canister not found")
            .clone()
    });
    let dns_client_canister_id = Principal::from_text(dns_client_canister_id_str).unwrap();
    let (fetched_public_key,): (Result<String, String>,) = ic_cdk::api::call::call(
        dns_client_canister_id,
        "get_dkim_public_key",
        (&selector, &domain, 40_000_000_000u64),
    )
    .await
    .map_err(|(code, e)| format!("dns_client canister error. {:?}, {}", code, e))?;
    let fetched_public_key = fetched_public_key?;
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _revoke_dkim_public_key: [fetched public key] {}",
                fetched_public_key
            ))
            .expect("failed to append log");
    });
    if revoked_public_key != fetched_public_key {
        return Err("public key mismatch".to_string());
    }
    let poseidon_canister_id_str = CONFIG.with(|config| {
        config
            .borrow()
            .get(&1)
            .expect("poseidon_canister not found")
            .clone()
    });
    let poseidon_canister_id = Principal::from_text(poseidon_canister_id_str).unwrap();
    let (res,): (Result<String, String>,) = ic_cdk::api::call::call(
        poseidon_canister_id,
        "public_key_hash",
        (fetched_public_key.clone(),),
    )
    .await
    .map_err(|(code, e)| format!("poseidon canister failed. {:?}, {}", code, e))?;
    let public_key_hash_hex = res?;
    let message = format!(
        "REVOKE:domain={};public_key_hash={};",
        domain, public_key_hash_hex
    );
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _revoke_dkim_public_key: [signed message] {}",
                message
            ))
            .expect("failed to append log");
    });
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

async fn create_ethereum_address() -> Result<String, String> {
    let res = ic_evm_sign::create_address(Principal::anonymous())
        .await
        .expect("create_address failed");
    Ok(res.address)
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

    // #[test]
    // fn test_sign_dkim_public_key() {
    //     // The following values are obtained by running the canister locally.
    //     let domain = "gmail.com";
    //     let public_key = "0x9edbd2293d6192a84a7b4c5c699d31f906e8b83b09b817dbcbf4bcda3c6ca02fd2a1d99f995b360f52801f79a2d40a9d31d535da1d957c44de389920198ab996377df7a009eee7764b238b42696168d1c7ecbc7e31d69bf3fcc337549dc4f0110e070cec0b111021f0435e51db415a2940011aee0d4db4767c32a76308aae634320642d63fe2e018e81f505e13e0765bd8f6366d0b443fa41ea8eb5c5b8aebb07db82fb5e10fe1d265bd61b22b6b13454f6e1273c43c08e0917cd795cc9d25636606145cff02c48d58d0538d96ab50620b28ad9f5aa685b528f41ef1bad24a546c8bdb1707fb6ee7a2e61bbb440cd9ab6795d4c106145000c13aeeedd678b05f";
    //     let pk_hash = "0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788";
    //     assert_eq!(public_key_hash(public_key.to_string()).unwrap(), pk_hash);
    //     let expected_msg = format!("SET:domain={};public_key_hash={};", domain, pk_hash);
    //     println!("expected_msg {}", expected_msg);
    //     let len = expected_msg.len();
    //     let len_string = len.to_string();
    //     const PREFIX: &str = "\x19Ethereum Signed Message:\n";
    //     let mut eth_message = Vec::with_capacity(PREFIX.len() + len_string.len() + len);
    //     eth_message.extend_from_slice(PREFIX.as_bytes());
    //     eth_message.extend_from_slice(len_string.as_bytes());
    //     eth_message.extend_from_slice(&expected_msg.as_bytes());
    //     println!("hash {}", hex::encode(raw_keccak256(eth_message).to_vec()));
    //     let signature = Signature::from_str("0x1989dad50b6635c11d365b7caca70cbeccdf37b201e0bc191d24e0842c9720184d14be94bac0b79213f87bf63daff4d34382ef55aed93688a393bd34330e00f01c").unwrap();
    //     let recovered = signature.recover(expected_msg).unwrap();
    //     assert_eq!(
    //         recovered,
    //         H160::from_slice(&hex::decode("1c63df16d1212ecf5d497984dfd1aa23904756ff").unwrap())
    //     );
    // }

    #[test]
    fn test_private_to_public() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let private_key_der = private_key.to_pkcs1_der().unwrap();

        let public_key_hex = {
            let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der.as_bytes())
                .expect("Invalid format private key");
            let public_key = private_key.to_public_key();
            assert!(public_key.e() == &BigUint::from(65537u64));
            "0x".to_string() + &hex::encode(&public_key.n().to_bytes_be())
        };

        assert_eq!(
            public_key_hex,
            "0x".to_string() + &hex::encode(&public_key.n().to_bytes_be())
        );
    }
}
