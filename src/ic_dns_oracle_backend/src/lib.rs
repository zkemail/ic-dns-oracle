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

/// Structure representing a signature for a new DKIM public key.
///
/// # Fields
/// - `selector`: The selector for the DKIM key.
/// - `domain`: The domain associated with the DKIM key.
/// - `signature`: The signature of the DKIM key.
/// - `public_key`: The public key itself.
#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct SignedDkimPublicKey {
    pub selector: String,
    pub domain: String,
    pub signature: String,
    pub public_key: String,
    pub public_key_hash: String,
}

/// Structure representing a signature for a revoked DKIM public key.
///
/// # Fields
/// - `selector`: The selector for the DKIM key.
/// - `domain`: The domain associated with the DKIM key.
/// - `signature`: The signature of the DKIM key.
/// - `public_key`: The public key itself.
/// - `public_key_hash`: The hash of the public key.
/// - `private_key`: The private key used to sign the revocation.
#[derive(Default, CandidType, Deserialize, Debug, Clone)]
pub struct SignedRevocation {
    pub selector: String,
    pub domain: String,
    pub signature: String,
    pub public_key: String,
    pub public_key_hash: String,
    pub private_key: String,
}

/// The memory manager is used for simulating multiple memories.
type Memory = VirtualMemory<DefaultMemoryImpl>;
thread_local! {
    /// Given a `MemoryId` it can return a memory that can be used by stable structures.
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// Initialize a `StableBTreeMap` with `MemoryId(0)`.
    static CONFIG: RefCell<StableBTreeMap<u8, String, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    /// Initialize a `StableLog` with `MemoryId(1)` and `MemoryId(2)`.
    static LOG: RefCell<StableLog<String, Memory, Memory>> = RefCell::new(
        StableLog::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
        ).expect("failed to init Log")
    );
}

/// Initializes the configuration of the environment for the evm signer, memory manager and the stable structures.
/// # Arguments
/// * `evn_opt` - The environment option of the evm signer.
/// * `poseidon_canister_id` - The canister id of the poseidon canister.
/// * `dns_client_canister_id` - The canister id of the dns client canister.
#[ic_cdk::init]
pub fn init(
    evn_opt: Option<Environment>,
    poseidon_canister_id: String,
    dns_client_canister_id: String,
) {
    _init(evn_opt, poseidon_canister_id, dns_client_canister_id);
}

/// The post-upgrade function for the canister.
/// It calls the post-upgrade function of the evm signer.
/// # Arguments
/// * `evn_opt` - The environment option of the evm signer.
/// * `poseidon_canister_id` - The canister id of the poseidon canister.
/// * `dns_client_canister_id` - The canister id of the dns client canister.
#[ic_cdk::post_upgrade]
pub fn post_upgrade_function(
    evn_opt: Option<Environment>,
    poseidon_canister_id: String,
    dns_client_canister_id: String,
) {
    _init(evn_opt, poseidon_canister_id, dns_client_canister_id);
    CONFIG.with(|config| {
        config.borrow_mut().remove(&0);
    });
}

/// Returns the ethereum address used for signing.
/// # Returns
/// The hex string of the ethereum address used for signing.
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

/// Returns the canister id of the poseidon canister.
/// # Returns
/// The canister id of the poseidon canister.
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

/// Returns the canister id of the dns client canister.
/// # Returns
/// The canister id of the dns client canister.
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

/// Returns the logs of the canister.
/// # Arguments
/// * `num_log` - The number of logs to return.
/// # Returns
/// The `num_log` log entries of the canister taken from the first log entry.
#[ic_cdk::query]
pub fn read_log_from_first(num_log: u64) -> Vec<String> {
    let mut logs = Vec::with_capacity(num_log as usize);
    let log_len = LOG.with(|log| log.borrow().len());
    assert!(
        num_log <= log_len,
        "num_log {} is greater than log length {}",
        num_log,
        log_len
    );
    for idx in 0..num_log {
        LOG.with(|log| {
            let mut buf = Vec::new();
            log.borrow()
                .read_entry(idx, &mut buf)
                .expect("failed to read log");
            logs.push(String::from_utf8(buf).unwrap());
        });
    }
    logs
}

/// Returns the logs of the canister.
/// # Arguments
/// * `num_log` - The number of logs to return.
/// # Returns
/// The `num_log` log entries of the canister taken from the last log entry.
#[ic_cdk::query]
pub fn read_log_from_last(num_log: u64) -> Vec<String> {
    let mut logs = Vec::with_capacity(num_log as usize);
    let log_len = LOG.with(|log| log.borrow().len());
    assert!(
        num_log <= log_len,
        "num_log {} is greater than log length {}",
        num_log,
        log_len
    );
    for idx in (log_len - num_log)..log_len {
        LOG.with(|log| {
            let mut buf = Vec::new();
            log.borrow()
                .read_entry(log_len - idx - 1, &mut buf)
                .expect("failed to read log");
            logs.push(String::from_utf8(buf).unwrap());
        });
    }
    logs
}

/// Signs a new DKIM public key fetched from Google DNS.
/// # Arguments
/// * `selector` - The selector for the DKIM key.
/// * `domain` - The domain associated with the DKIM key.
/// # Returns
/// The signed DKIM public key.
/// # Errors
/// An error message is returned if 1) the public key is not found or 2) the signing fails,
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

fn _init(
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

async fn _sign_dkim_public_key(
    selector: String,
    domain: String,
) -> Result<SignedDkimPublicKey, String> {
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    /// Accept all available cycles.
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
        /// Generate ethereum address if it has not been set yet.
        LOG.with(|log| {
            log.borrow_mut()
                .append(&format!(
                    "fn _sign_dkim_public_key: [before creating ethereum address]"
                ))
                .expect("failed to append log")
        });
        let address = create_ethereum_address().await?;
        LOG.with(|log| {
            log.borrow_mut()
                .append(&format!(
                    "fn _sign_dkim_public_key: [after creating ethereum address] {}",
                    address
                ))
                .expect("failed to append log")
        });
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
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _sign_dkim_public_key: [before calling get_dkim_public_key]"
            ))
            .expect("failed to append log")
    });
    /// Fetch the public key from Google DNS.
    let (public_key,): (Result<String, String>,) = ic_cdk::api::call::call(
        dns_client_canister_id,
        "get_dkim_public_key",
        (&selector, &domain, 40_000_000_000u64),
    )
    .await
    .map_err(|(code, e)| format!("dns_client canister error. {:?}, {}", code, e))?;
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _sign_dkim_public_key: [after calling get_dkim_public_key]"
            ))
            .expect("failed to append log")
    });
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
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _sign_dkim_public_key: [before calling public_key_hash]"
            ))
            .expect("failed to append log")
    });
    /// Compute the hash of the public key.
    let (res,): (Result<String, String>,) = ic_cdk::api::call::call(
        poseidon_canister_id,
        "public_key_hash",
        (public_key.clone(),),
    )
    .await
    .map_err(|(code, e)| format!("poseidon canister error. {:?}, {}", code, e))?;
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _sign_dkim_public_key: [after calling public_key_hash]"
            ))
            .expect("failed to append log")
    });
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
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _sign_dkim_public_key: [before ic_evm_signing]"
            ))
            .expect("failed to append log")
    });
    /// Sign the message.
    let signature =
        ic_evm_sign::sign_msg(message.as_bytes().to_vec(), Principal::anonymous()).await?;
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!("fn _sign_dkim_public_key: [after ic_evm_signing]"))
            .expect("failed to append log")
    });
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _sign_dkim_public_key: [signature] {}",
                signature
            ))
            .expect("failed to append log");
    });
    let res = SignedDkimPublicKey {
        selector,
        domain: domain.clone(),
        signature,
        public_key,
        public_key_hash: public_key_hash_hex,
    };
    Ok(res)
}

/// Signs a revoked DKIM public key corresponding to the given private key.
/// # Arguments
/// * `selector` - The selector for the DKIM key.
/// * `domain` - The domain associated with the DKIM key.
/// * `private_key_der` - The private key corresponding to the public key to be revoked.
/// # Returns
/// The signed revocation of the DKIM public key.
/// # Errors
/// An error message is returned if 1) the public key is not found in DNS, 2) the fecth public key does not match with that derived from the given private key, or 3) the signing fails,
#[ic_cdk::update]
pub async fn revoke_dkim_public_key(
    selector: String,
    domain: String,
    private_key_der: String,
) -> Result<SignedRevocation, String> {
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn revoke_dkim_public_key: [input] selector {}, domain {}, private_key {}",
                selector, domain, private_key_der
            ))
            .expect("failed to append log");
    });
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
    /// Accept all available cycles.
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
    /// Generate the public key from the private key.
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
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _revoke_dkim_public_key: [before calling get_dkim_public_key]"
            ))
            .expect("failed to append log")
    });
    /// Fetch the public key from Google DNS.
    let (fetched_public_key,): (Result<String, String>,) = ic_cdk::api::call::call(
        dns_client_canister_id,
        "get_dkim_public_key",
        (&selector, &domain, 40_000_000_000u64),
    )
    .await
    .map_err(|(code, e)| format!("dns_client canister error. {:?}, {}", code, e))?;
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _revoke_dkim_public_key: [after calling get_dkim_public_key]"
            ))
            .expect("failed to append log")
    });
    let fetched_public_key = fetched_public_key?;
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _revoke_dkim_public_key: [fetched public key] {}",
                fetched_public_key
            ))
            .expect("failed to append log");
    });
    /// Check if the fetched public key matches with the derived public key.
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
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _revoke_dkim_public_key: [before calling public_key_hash]"
            ))
            .expect("failed to append log")
    });
    /// Compute the hash of the public key.
    let (res,): (Result<String, String>,) = ic_cdk::api::call::call(
        poseidon_canister_id,
        "public_key_hash",
        (fetched_public_key.clone(),),
    )
    .await
    .map_err(|(code, e)| format!("poseidon canister failed. {:?}, {}", code, e))?;
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _revoke_dkim_public_key: [after calling public_key_hash]"
            ))
            .expect("failed to append log")
    });
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
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _revoke_dkim_public_key: [before ic_evm_signing]"
            ))
            .expect("failed to append log");
    });
    /// Sign the message.
    let signature =
        ic_evm_sign::sign_msg(message.as_bytes().to_vec(), Principal::anonymous()).await?;
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _revoke_dkim_public_key: [after ic_evm_signing]"
            ))
            .expect("failed to append log");
    });
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!(
                "fn _revoke_dkim_public_key: [signature] {}",
                signature
            ))
            .expect("failed to append log");
    });
    let res = SignedRevocation {
        selector,
        domain: domain.clone(),
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

ic_cdk::export_candid!();
