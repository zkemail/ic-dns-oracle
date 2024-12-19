#![allow(non_snake_case, non_upper_case_globals)]
use candid::{CandidType, Principal};
use hex;
use ic_evm_sign;
use ic_evm_sign::state::Environment;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableLog};
use rsa::{pkcs1::DecodeRsaPrivateKey, traits::PublicKeyParts, BigUint, RsaPrivateKey};
use serde::Deserialize;
use std::cell::RefCell;

// consumed cycle for sign_dkim_public_key: 26_164_599_060 cycles
// the consumed cycle * 1.5 is charged cycle = 39_246_898_590 cycles
pub const SIGN_CHARGED_CYCLE1: u128 = 39_246_898_590;

// consumed cycle for sign_dkim_public_key: 26_164_599_060 cycles
// the consumed cycle * 1.5 is charged cycle = 39_246_898_590 cycles
pub const SIGN_CHARGED_CYCLE2: u128 = 39_246_898_590;

// consumed cycle for revoke_dkim_public_key: 26_254_964_417 cycles
// the consumed cycle * 1.5 is charged cycle = 39_382_446_626 cycles
pub const REVOKE_CHARGED_CYCLE1: u128 = 39_382_446_626;

// consumed cycle for revoke_dkim_public_key: 26_254_964_417 cycles
// the consumed cycle * 1.5 is charged cycle = 39_382_446_626 cycles
pub const REVOKE_CHARGED_CYCLE2: u128 = 39_382_446_626;

// consumed cycle for get_dkim_public_key: 735_324_690 cycles
// the consumed cycle * 1.5 is charged cycle = 1_102_987_035 cycles
pub const DNS_CLIENT_CHARGED_CYCLE: u128 = 1_102_987_035;

// consumed cycle for public_key_hash: 17_610_659 cycles
// the consumed cycle * 1.5 is charged cycle = 26_415_989 cycles
pub const POSEIDON_CHARGED_CYCLE: u128 = 26_415_989;

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

/// Returns the signer's ethereum address used for signing.
/// # Returns
/// The hex string of the ethereum address used for signing.
#[ic_cdk::query]
pub fn get_signer_ethereum_address() -> String {
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

/// Initializes the signer's ethereum address used for signing.
/// If the ethereum address has not been set yet, it generates a new ethereum address.
/// # Returns
/// The hex string of the ethereum address used for signing.
#[ic_cdk::update]
pub async fn init_signer_ethereum_address() -> String {
    write_log("init_signer_ethereum_address", "");
    let is_null = CONFIG.with(|config| config.borrow().get(&0).is_none());
    if !is_null {
        write_log("init_signer_ethereum_address", "[ethereum address found]");
        return get_signer_ethereum_address();
    }
    write_log(
        "init_signer_ethereum_address",
        "[before creating ethereum address]",
    );
    let address = create_ethereum_address()
        .await
        .expect("failed to create ethereum address");
    write_log(
        "init_signer_ethereum_address",
        &format!("[after creating ethereum address] {}", address),
    );
    CONFIG.with(|config| {
        config.borrow_mut().insert(0, address.clone());
    });
    write_log(
        "init_signer_ethereum_address",
        &format!("[generated ethereum address] {}", address),
    );
    address
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
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    #[cfg(not(debug_assertions))]
    {
        if available_cycles < SIGN_CHARGED_CYCLE1 {
            return Err("Insufficient cycles".to_string());
        }
    }
    // Accept all available cycles.
    let accepted_cycles = ic_cdk::api::call::msg_cycles_accept128(SIGN_CHARGED_CYCLE1);
    if available_cycles != accepted_cycles {
        return Err("Fail to accept all available cycles".to_string());
    }
    write_log(
        "sign_dkim_public_key",
        &format!(
            "[input] selector {}, domain {}, available_cycles {}",
            selector, domain, available_cycles
        ),
    );
    let domain_with_gappssmtp =
        format!("{}.{}.gappssmtp.com", &domain.replace(".", "-"), &selector);
    let error0 = match _sign_dkim_public_key(selector.clone(), domain.clone(), domain.clone()).await
    {
        Ok(res) => {
            write_log(
                "sign_dkim_public_key",
                &format!("[first try output] {:?}", res),
            );
            return Ok(res);
        }
        Err(e) => e,
    };
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    #[cfg(not(debug_assertions))]
    {
        if available_cycles < SIGN_CHARGED_CYCLE2 {
            return Err("Insufficient cycles".to_string());
        }
    }
    // Accept all available cycles.
    let accepted_cycles = ic_cdk::api::call::msg_cycles_accept128(SIGN_CHARGED_CYCLE2);
    if available_cycles != accepted_cycles {
        return Err("Fail to accept all available cycles".to_string());
    }
    let error1 = match _sign_dkim_public_key(selector, domain_with_gappssmtp, domain.clone()).await
    {
        Ok(res) => {
            write_log(
                "sign_dkim_public_key",
                &format!(
                    "[first try error] {}, [second try output] {:?}",
                    error0, res
                ),
            );
            return Ok(res);
        }
        Err(e) => e,
    };
    write_log(
        "sign_dkim_public_key",
        &format!(
            "[first try error] {}, [second try error] {}",
            error0, error1
        ),
    );
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
    signed_domain: String,
) -> Result<SignedDkimPublicKey, String> {
    write_log(
        "_sign_dkim_public_key",
        &format!("[input] selector {}, domain {}", selector, domain),
    );
    let is_null_addr = CONFIG.with(|config| config.borrow().get(&0).is_none());
    if is_null_addr {
        // Generate ethereum address if it has not been set yet.
        write_log(
            "_sign_dkim_public_key",
            "[before creating ethereum address]",
        );
        let address = create_ethereum_address().await?;
        write_log(
            "_sign_dkim_public_key",
            &format!("[after creating ethereum address] {}", address),
        );
        CONFIG.with(|config| {
            config.borrow_mut().insert(0, address.clone());
        });
        write_log(
            "_sign_dkim_public_key",
            &format!("[generated ethereum address] {}", address),
        );
    }
    let dns_client_canister_id_str = CONFIG.with(|config| {
        config
            .borrow()
            .get(&2)
            .expect("dns_client_canister not found")
            .clone()
    });
    let dns_client_canister_id = Principal::from_text(dns_client_canister_id_str).unwrap();
    write_log(
        "_sign_dkim_public_key",
        "[before calling get_dkim_public_key]",
    );
    // Fetch the public key from Google DNS.
    let (public_key,): (Result<String, String>,) = ic_cdk::api::call::call_with_payment128(
        dns_client_canister_id,
        "get_dkim_public_key",
        (&selector, &domain, 40_000_000_000u64),
        DNS_CLIENT_CHARGED_CYCLE,
    )
    .await
    .map_err(|(code, e)| format!("dns_client canister error. {:?}, {}", code, e))?;
    write_log(
        "_sign_dkim_public_key",
        "[after calling get_dkim_public_key]",
    );
    let public_key = public_key?;
    write_log(
        "_sign_dkim_public_key",
        &format!("[fetched public key] {}", public_key),
    );
    let poseidon_canister_id_str = CONFIG.with(|config| {
        config
            .borrow()
            .get(&1)
            .expect("poseidon_canister not found")
            .clone()
    });
    let poseidon_canister_id = Principal::from_text(poseidon_canister_id_str).unwrap();
    write_log("_sign_dkim_public_key", "[before calling public_key_hash]");
    // Compute the hash of the public key.
    let (res,): (Result<String, String>,) = ic_cdk::api::call::call_with_payment128(
        poseidon_canister_id,
        "public_key_hash",
        (public_key.clone(),),
        POSEIDON_CHARGED_CYCLE,
    )
    .await
    .map_err(|(code, e)| format!("poseidon canister error. {:?}, {}", code, e))?;
    write_log("_sign_dkim_public_key", "[after calling public_key_hash]");
    let public_key_hash_hex = res?;
    let message = format!(
        "SET:domain={};public_key_hash={};",
        signed_domain, public_key_hash_hex
    );
    write_log(
        "_sign_dkim_public_key",
        &format!("[signed message] {}", message),
    );
    write_log("_sign_dkim_public_key", "[before ic_evm_signing]");
    // Sign the message.
    let signature =
        ic_evm_sign::sign_msg(message.as_bytes().to_vec(), Principal::anonymous()).await?;
    write_log("_sign_dkim_public_key", "[after ic_evm_signing]");
    write_log(
        "_sign_dkim_public_key",
        &format!("[signature] {}", signature),
    );
    let res = SignedDkimPublicKey {
        selector,
        domain: signed_domain.clone(),
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
/// * `private_key_der_hex` - The private key corresponding to the public key to be revoked.
/// # Returns
/// The signed revocation of the DKIM public key.
/// # Errors
/// An error message is returned if 1) the public key is not found in DNS, 2) the fecth public key does not match with that derived from the given private key, or 3) the signing fails,
#[ic_cdk::update]
pub async fn revoke_dkim_public_key(
    selector: String,
    domain: String,
    private_key_der_hex: String,
) -> Result<SignedRevocation, String> {
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    #[cfg(not(debug_assertions))]
    {
        if available_cycles < REVOKE_CHARGED_CYCLE1 {
            return Err("Insufficient cycles".to_string());
        }
    }
    // Accept all available cycles.
    let accepted_cycles = ic_cdk::api::call::msg_cycles_accept128(REVOKE_CHARGED_CYCLE1);
    if available_cycles != accepted_cycles {
        return Err("Fail to accept all available cycles".to_string());
    }
    write_log(
        "revoke_dkim_public_key",
        &format!(
            "[input] selector {}, domain {}, private_key_der_hex {}",
            selector, domain, private_key_der_hex
        ),
    );
    let error0 = match _revoke_dkim_public_key(
        selector.clone(),
        domain.clone(),
        domain.clone(),
        private_key_der_hex.clone(),
    )
    .await
    {
        Ok(res) => {
            write_log(
                "revoke_dkim_public_key",
                &format!("[first try output] {:?}", res),
            );
            return Ok(res);
        }
        Err(e) => e,
    };
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    #[cfg(not(debug_assertions))]
    {
        if available_cycles < REVOKE_CHARGED_CYCLE2 {
            return Err("Insufficient cycles".to_string());
        }
    }
    // Accept all available cycles.
    let accepted_cycles = ic_cdk::api::call::msg_cycles_accept128(REVOKE_CHARGED_CYCLE2);
    if available_cycles != accepted_cycles {
        return Err("Fail to accept all available cycles".to_string());
    }
    let domain_with_gappssmtp =
        format!("{}.{}.gappssmtp.com", &domain.replace(".", "-"), &selector);
    let error1 = match _revoke_dkim_public_key(
        selector,
        domain_with_gappssmtp,
        domain.clone(),
        private_key_der_hex,
    )
    .await
    {
        Ok(res) => {
            write_log(
                "revoke_dkim_public_key",
                &format!(
                    "[first try error] {}, [second try output] {:?}",
                    error0, res
                ),
            );
            return Ok(res);
        }
        Err(e) => e,
    };
    write_log(
        "revoke_dkim_public_key",
        &format!(
            "[first try error] {}, [second try error] {}",
            error0, error1
        ),
    );
    Err(format!(
        "any revocation failed. error0: {}, error1: {}",
        error0, error1
    ))
}

async fn _revoke_dkim_public_key(
    selector: String,
    domain: String,
    signed_domain: String,
    private_key_der_hex: String,
) -> Result<SignedRevocation, String> {
    write_log(
        "_revoke_dkim_public_key",
        &format!(
            "[input] selector {}, domain {}, private_key_der_hex {}",
            selector, domain, private_key_der_hex
        ),
    );
    if CONFIG.with(|config| config.borrow().get(&0).is_none()) {
        return Err("ethereum address not found".to_string());
    }
    // Generate the public key from the private key.
    let revoked_public_key = {
        let private_key = RsaPrivateKey::from_pkcs1_der(
            &hex::decode(&private_key_der_hex[2..])
                .map_err(|e| format!("invalid private key hex. {}", e))?,
        )
        .map_err(|e| format!("Invalid format private key: {}", e))?;
        let public_key = private_key.to_public_key();
        if public_key.e() != &BigUint::from(65537u64) {
            return Err("invalid e parameter of public key".to_string());
        }
        "0x".to_string() + &hex::encode(&public_key.n().to_bytes_be())
    };
    write_log(
        "_revoke_dkim_public_key",
        &format!("[revoked public key] {}", revoked_public_key),
    );
    let dns_client_canister_id_str = CONFIG.with(|config| {
        config
            .borrow()
            .get(&2)
            .expect("dns_client_canister not found")
            .clone()
    });
    let dns_client_canister_id = Principal::from_text(dns_client_canister_id_str).unwrap();
    write_log(
        "_revoke_dkim_public_key",
        "[before calling get_dkim_public_key]",
    );
    // Fetch the public key from Google DNS.
    let (fetched_public_key,): (Result<String, String>,) = ic_cdk::api::call::call_with_payment128(
        dns_client_canister_id,
        "get_dkim_public_key",
        (&selector, &domain, 40_000_000_000u64),
        DNS_CLIENT_CHARGED_CYCLE,
    )
    .await
    .map_err(|(code, e)| format!("dns_client canister error. {:?}, {}", code, e))?;
    write_log(
        "_revoke_dkim_public_key",
        "[after calling get_dkim_public_key]",
    );
    let fetched_public_key = fetched_public_key?;
    write_log(
        "_revoke_dkim_public_key",
        &format!("[fetched public key] {}", fetched_public_key),
    );
    // Check if the fetched public key matches with the derived public key.
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
    write_log(
        "_revoke_dkim_public_key",
        "[before calling public_key_hash]",
    );
    // Compute the hash of the public key.
    let (res,): (Result<String, String>,) = ic_cdk::api::call::call_with_payment128(
        poseidon_canister_id,
        "public_key_hash",
        (fetched_public_key.clone(),),
        POSEIDON_CHARGED_CYCLE,
    )
    .await
    .map_err(|(code, e)| format!("poseidon canister failed. {:?}, {}", code, e))?;
    write_log("_revoke_dkim_public_key", "[after calling public_key_hash]");
    let public_key_hash_hex = res?;
    let message = format!(
        "REVOKE:domain={};public_key_hash={};",
        signed_domain, public_key_hash_hex
    );
    write_log(
        "_revoke_dkim_public_key",
        &format!("[signed message] {}", message),
    );
    write_log("_revoke_dkim_public_key", "[before ic_evm_signing]");
    // Sign the message.
    let signature =
        ic_evm_sign::sign_msg(message.as_bytes().to_vec(), Principal::anonymous()).await?;
    write_log("_revoke_dkim_public_key", "[after ic_evm_signing]");
    write_log(
        "_revoke_dkim_public_key",
        &format!("[signature] {}", signature),
    );
    let res = SignedRevocation {
        selector,
        domain: signed_domain.clone(),
        signature,
        public_key: fetched_public_key,
        public_key_hash: public_key_hash_hex,
        private_key: private_key_der_hex,
    };
    Ok(res)
}

async fn create_ethereum_address() -> Result<String, String> {
    let res = ic_evm_sign::create_address(Principal::anonymous())
        .await
        .expect("create_address failed");
    Ok(res.address)
}

fn write_log(fn_name: &str, msg: &str) {
    let current_time = ic_cdk::api::time();
    LOG.with(|log| {
        log.borrow_mut()
            .append(&format!("[{}] fn {}: {}", current_time, fn_name, msg))
            .expect("failed to append log");
    });
}

ic_cdk::export_candid!();

#[cfg(test)]
mod test {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};
    use candid::{decode_one, encode_one, Encode, Principal};
    use easy_hasher::easy_hasher::raw_keccak256;
    use hex;
    use libsecp256k1;
    use pocket_ic::{
        common::rest::{CanisterHttpReply, CanisterHttpResponse, MockCanisterHttpResponse},
        PocketIc, PocketIcBuilder, WasmResult,
    };
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::rand_core::OsRng;

    const PUBLIC_KEY: &'static str = "0x9edbd2293d6192a84a7b4c5c699d31f906e8b83b09b817dbcbf4bcda3c6ca02fd2a1d99f995b360f52801f79a2d40a9d31d535da1d957c44de389920198ab996377df7a009eee7764b238b42696168d1c7ecbc7e31d69bf3fcc337549dc4f0110e070cec0b111021f0435e51db415a2940011aee0d4db4767c32a76308aae634320642d63fe2e018e81f505e13e0765bd8f6366d0b443fa41ea8eb5c5b8aebb07db82fb5e10fe1d265bd61b22b6b13454f6e1273c43c08e0917cd795cc9d25636606145cff02c48d58d0538d96ab50620b28ad9f5aa685b528f41ef1bad24a546c8bdb1707fb6ee7a2e61bbb440cd9ab6795d4c106145000c13aeeedd678b05f";
    const PUBLIC_KEY_HASH: &'static str =
        "0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788";

    #[test]
    fn test_private_to_public() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let private_key_der = private_key.to_pkcs1_der().unwrap();
        let public_key_hex = private_key_der_to_public_key_hex(&private_key_der.as_bytes());

        assert_eq!(
            public_key_hex,
            "0x".to_string() + &hex::encode(&public_key.n().to_bytes_be())
        );
    }

    #[test]
    fn test_sign_gmail() {
        let (pic, canister_id) = test_setup();

        // Init the signer's ethereum address.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "init_signer_ethereum_address",
                encode_one(()).unwrap(),
            )
            .unwrap();

        let reply = pic.await_call(call_id).unwrap();
        let signer_addr = match reply {
            WasmResult::Reply(data) => {
                let res: String = decode_one(&data).unwrap();
                res
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };

        // Submit an update call to the test canister making a canister http outcall
        // and mock a canister http outcall response.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "sign_dkim_public_key",
                Encode!(&"20230601", &"gmail.com").unwrap(),
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
        pic.tick();
        pic.tick();
        mock_http_response(&pic, body);
        pic.tick();
        mock_http_response(&pic, body);

        // // Now the test canister will receive the http outcall response
        // // and reply to the ingress message from the test driver.
        let reply = pic.await_call(call_id).unwrap();
        let res = match reply {
            WasmResult::Reply(data) => {
                let res: Result<SignedDkimPublicKey, String> = decode_one(&data).unwrap();
                res.unwrap()
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
        assert_eq!(res.selector, "20230601");
        assert_eq!(res.domain, "gmail.com");
        assert_eq!(res.public_key, PUBLIC_KEY);
        assert_eq!(res.public_key_hash, PUBLIC_KEY_HASH);
        // // There should be no more pending canister http outcalls.
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);

        let signature = hex::decode(&res.signature[2..]).unwrap();
        let signature_bytes: [u8; 64] = signature[0..64].try_into().unwrap();
        let signature_bytes_64 = libsecp256k1::Signature::parse_standard(&signature_bytes).unwrap();
        let recovery_id =
            libsecp256k1::RecoveryId::parse(u8::try_from(signature[64]).unwrap() - 27).unwrap();

        let message = format!(
            "SET:domain={};public_key_hash={};",
            res.domain, res.public_key_hash
        );
        let message_hash = msg_to_hash(&message.as_bytes());
        let public_key = libsecp256k1::recover(
            &libsecp256k1::Message::parse(&message_hash),
            &signature_bytes_64,
            &recovery_id,
        )
        .unwrap();
        let recovered_addr =
            ic_evm_sign::get_address_from_public_key(public_key.serialize_compressed().to_vec())
                .unwrap();
        assert_eq!(recovered_addr.to_string(), signer_addr);
    }

    #[test]
    fn test_sign_gappssmtp() {
        let (pic, canister_id) = test_setup();

        // Init the signer's ethereum address.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "init_signer_ethereum_address",
                encode_one(()).unwrap(),
            )
            .unwrap();
        let reply = pic.await_call(call_id).unwrap();
        let signer_addr = match reply {
            WasmResult::Reply(data) => {
                let res: String = decode_one(&data).unwrap();
                res
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };

        // Submit an update call to the test canister making a canister http outcall
        // and mock a canister http outcall response.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "sign_dkim_public_key",
                Encode!(&"20230601", &"zeroknowledge.fm").unwrap(),
            )
            .unwrap();

        let body = r#"
            {"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"20230601._domainkey.zeroknowledge-fm.20230601.gappssmtp.com.","type":16}],"Answer":[],"Comment":"Response from 216.239.38.99."}
            "#;
        pic.tick();
        pic.tick();
        mock_http_response(&pic, body);
        pic.tick();
        mock_http_response(&pic, body);
        pic.tick();
        mock_http_response(&pic, body);
        pic.tick();

        let body = r#"
            {"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"20230601._domainkey.zeroknowledge-fm.20230601.gappssmtp.com.","type":16}],"Answer":[{"name":"20230601._domainkey.zeroknowledge-fm.20230601.gappssmtp.com.","type":16,"TTL":3600,"data":"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3gWcOhCm99qzN+h7/2+LeP3CLsJkQQ4EP/2mrceXle5pKq8uZmBl1U4d2Vxn4w+pWFANDLmcHolLboESLFqEL5N6ae7u9b236dW4zn9AFkXAGenTzQEeif9VUFtLAZ0Qh2eV7OQgz/vPj5IaNqJ7h9hpM9gO031fe4v+J0DLCE8Rgo7hXbNgJavctc0983DaCDQaznHZ44LZ6TtZv9TBs+QFvsy4+UCTfsuOtHzoEqOOuXsVXZKLP6B882XbEnBpXEF8QzV4J26HiAJFUbO3mAqZL2UeKC0hhzoIZqZXNG0BfuzOF0VLpDa18GYMUiu+LhEJPJO9D8zhzvQIHNrpGwIDAQAB"}],"Comment":"Response from 216.239.38.99."}
            "#;
        pic.tick();
        pic.tick();
        mock_http_response(&pic, body);
        pic.tick();
        mock_http_response(&pic, body);

        // // Now the test canister will receive the http outcall response
        // // and reply to the ingress message from the test driver.
        let reply = pic.await_call(call_id).unwrap();
        let res = match reply {
            WasmResult::Reply(data) => {
                let res: Result<SignedDkimPublicKey, String> = decode_one(&data).unwrap();
                res.unwrap()
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
        assert_eq!(res.selector, "20230601");
        assert_eq!(res.domain, "zeroknowledge.fm");
        assert_eq!(res.public_key, "0xde059c3a10a6f7dab337e87bff6f8b78fdc22ec264410e043ffda6adc79795ee692aaf2e666065d54e1dd95c67e30fa958500d0cb99c1e894b6e81122c5a842f937a69eeeef5bdb7e9d5b8ce7f401645c019e9d3cd011e89ff55505b4b019d10876795ece420cffbcf8f921a36a27b87d86933d80ed37d5f7b8bfe2740cb084f11828ee15db36025abdcb5cd3df370da08341ace71d9e382d9e93b59bfd4c1b3e405beccb8f940937ecb8eb47ce812a38eb97b155d928b3fa07cf365db1270695c417c433578276e8788024551b3b7980a992f651e282d21873a0866a657346d017eecce17454ba436b5f0660c522bbe2e11093c93bd0fcce1cef4081cdae91b");
        assert_eq!(
            res.public_key_hash,
            "0x1f41be830e3f38f638195af065c7de98c05aa979b448a464ef4d13c01f7d0d3c"
        );
        // There should be no more pending canister http outcalls.
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
        let signature = hex::decode(&res.signature[2..]).unwrap();
        let signature_bytes: [u8; 64] = signature[0..64].try_into().unwrap();
        let signature_bytes_64 = libsecp256k1::Signature::parse_standard(&signature_bytes).unwrap();
        let recovery_id =
            libsecp256k1::RecoveryId::parse(u8::try_from(signature[64]).unwrap() - 27).unwrap();

        let message = format!(
            "SET:domain={};public_key_hash={};",
            res.domain, res.public_key_hash
        );
        let message_hash = msg_to_hash(&message.as_bytes());
        let public_key = libsecp256k1::recover(
            &libsecp256k1::Message::parse(&message_hash),
            &signature_bytes_64,
            &recovery_id,
        )
        .unwrap();
        let recovered_addr =
            ic_evm_sign::get_address_from_public_key(public_key.serialize_compressed().to_vec())
                .unwrap();
        assert_eq!(recovered_addr.to_string(), signer_addr);
    }

    #[test]
    fn test_revoke_valid_case() {
        let (pic, canister_id) = test_setup();

        // Init the signer's ethereum address.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "init_signer_ethereum_address",
                encode_one(()).unwrap(),
            )
            .unwrap();
        let reply = pic.await_call(call_id).unwrap();
        let signer_addr = match reply {
            WasmResult::Reply(data) => {
                let res: String = decode_one(&data).unwrap();
                res
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };

        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let private_key_der = private_key.to_pkcs1_der().unwrap();
        let private_key_der_hex = "0x".to_string() + &hex::encode(&private_key_der.as_bytes());
        let public_key_hex = private_key_der_to_public_key_hex(&private_key_der.as_bytes());
        let public_key_der = private_key.to_public_key().to_pkcs1_der().unwrap();
        let public_key_der_base64 = general_purpose::STANDARD.encode(&public_key_der.as_bytes());

        // Submit an update call to the test canister making a canister http outcall
        // and mock a canister http outcall response.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "revoke_dkim_public_key",
                Encode!(&"20230601", &"gmail.com", &private_key_der_hex.to_string()).unwrap(),
            )
            .unwrap();

        let mut body = r#"
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
                    "data": "v=DKIM1; k=rsa; p={{BASE64}}"
                }
            ],
            "Comment": "Response from 216.239.32.10."
        }
        "#
        .to_string();
        body = body.replace("{{BASE64}}", &public_key_der_base64);
        pic.tick();
        pic.tick();
        mock_http_response(&pic, &body);
        pic.tick();
        mock_http_response(&pic, &body);

        // Now the test canister will receive the http outcall response
        // and reply to the ingress message from the test driver.
        let reply = pic.await_call(call_id).unwrap();
        let res = match reply {
            WasmResult::Reply(data) => {
                let res: Result<SignedDkimPublicKey, String> = decode_one(&data).unwrap();
                res.unwrap()
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
        assert_eq!(res.selector, "20230601");
        assert_eq!(res.domain, "gmail.com");
        assert_eq!(res.public_key, public_key_hex);
        // There should be no more pending canister http outcalls.
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
        let signature = hex::decode(&res.signature[2..]).unwrap();
        let signature_bytes: [u8; 64] = signature[0..64].try_into().unwrap();
        let signature_bytes_64 = libsecp256k1::Signature::parse_standard(&signature_bytes).unwrap();
        let recovery_id =
            libsecp256k1::RecoveryId::parse(u8::try_from(signature[64]).unwrap() - 27).unwrap();

        let message = format!(
            "REVOKE:domain={};public_key_hash={};",
            res.domain, res.public_key_hash
        );
        let message_hash = msg_to_hash(&message.as_bytes());
        let public_key = libsecp256k1::recover(
            &libsecp256k1::Message::parse(&message_hash),
            &signature_bytes_64,
            &recovery_id,
        )
        .unwrap();
        let recovered_addr =
            ic_evm_sign::get_address_from_public_key(public_key.serialize_compressed().to_vec())
                .unwrap();
        assert_eq!(recovered_addr.to_string(), signer_addr);
    }

    #[test]
    fn test_revoke_valid_case_gappssmtp() {
        let (pic, canister_id) = test_setup();

        // Init the signer's ethereum address.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "init_signer_ethereum_address",
                encode_one(()).unwrap(),
            )
            .unwrap();
        let reply = pic.await_call(call_id).unwrap();
        let signer_addr = match reply {
            WasmResult::Reply(data) => {
                let res: String = decode_one(&data).unwrap();
                res
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };

        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let private_key_der = private_key.to_pkcs1_der().unwrap();
        let private_key_der_hex = "0x".to_string() + &hex::encode(&private_key_der.as_bytes());
        let public_key_hex = private_key_der_to_public_key_hex(&private_key_der.as_bytes());
        let public_key_der = private_key.to_public_key().to_pkcs1_der().unwrap();
        let public_key_der_base64 = general_purpose::STANDARD.encode(&public_key_der.as_bytes());

        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "revoke_dkim_public_key",
                Encode!(&"20230601", &"gmail.com", &private_key_der_hex.to_string()).unwrap(),
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
                    "name": "20230601.gmail.com.",
                    "type": 16
                }
            ],
            "Comment": "Response from 216.239.32.10."
        }
        "#
        .to_string();
        pic.tick();
        pic.tick();
        mock_http_response(&pic, &body);
        pic.tick();
        mock_http_response(&pic, &body);
        pic.tick();
        mock_http_response(&pic, &body);
        pic.tick();

        let mut body = r#"
        {
            "Status": 0,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": false,
            "CD": false,
            "Question": [
                {
                    "name": "20230601._domainkey.gmail-com.20230601.gappssmtp.com.",
                    "type": 16
                }
            ],
            "Answer": [
                {
                    "name": "20230601._domainkey.gmail-com.20230601.gappssmtp.com.",
                    "type": 16,
                    "TTL": 3600,
                    "data": "v=DKIM1; k=rsa; p={{BASE64}}"
                }
            ],
            "Comment": "Response from 216.239.32.10."
        }
        "#
        .to_string();
        body = body.replace("{{BASE64}}", &public_key_der_base64);
        pic.tick();
        pic.tick();
        mock_http_response(&pic, &body);
        pic.tick();
        mock_http_response(&pic, &body);
        pic.tick();

        let reply = pic.await_call(call_id).unwrap();
        let res = match reply {
            WasmResult::Reply(data) => {
                let res: Result<SignedDkimPublicKey, String> = decode_one(&data).unwrap();
                res.unwrap()
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };

        assert_eq!(res.selector, "20230601");
        assert_eq!(res.domain, "gmail.com");
        assert_eq!(res.public_key, public_key_hex);
        // There should be no more pending canister http outcalls.
        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
        let signature = hex::decode(&res.signature[2..]).unwrap();
        let signature_bytes: [u8; 64] = signature[0..64].try_into().unwrap();
        let signature_bytes_64 = libsecp256k1::Signature::parse_standard(&signature_bytes).unwrap();
        let recovery_id =
            libsecp256k1::RecoveryId::parse(u8::try_from(signature[64]).unwrap() - 27).unwrap();

        let message = format!(
            "REVOKE:domain={};public_key_hash={};",
            res.domain, res.public_key_hash
        );
        let message_hash = msg_to_hash(&message.as_bytes());
        let public_key = libsecp256k1::recover(
            &libsecp256k1::Message::parse(&message_hash),
            &signature_bytes_64,
            &recovery_id,
        )
        .unwrap();
        let recovered_addr =
            ic_evm_sign::get_address_from_public_key(public_key.serialize_compressed().to_vec())
                .unwrap();
        assert_eq!(recovered_addr.to_string(), signer_addr);
    }

    #[test]
    fn test_revoke_key_mismatch_case() {
        let (pic, canister_id) = test_setup();

        // Init the signer's ethereum address.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "init_signer_ethereum_address",
                encode_one(()).unwrap(),
            )
            .unwrap();
        let _ = pic.await_call(call_id).unwrap();

        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let private_key_der = private_key.to_pkcs1_der().unwrap();
        let private_key_der_hex = "0x".to_string() + &hex::encode(&private_key_der.as_bytes());

        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "revoke_dkim_public_key",
                Encode!(&"20230601", &"gmail.com", &private_key_der_hex.to_string()).unwrap(),
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
                    "name": "20230601.gmail.com.",
                    "type": 16
                }
            ],
            "Comment": "Response from 216.239.32.10."
        }
        "#
        .to_string();
        pic.tick();
        pic.tick();
        mock_http_response(&pic, &body);
        pic.tick();
        mock_http_response(&pic, &body);
        pic.tick();
        mock_http_response(&pic, &body);
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
                    "name": "20230601._domainkey.gmail-com.20230601.gappssmtp.com.",
                    "type": 16
                }
            ],
            "Answer": [
                {
                    "name": "20230601._domainkey.gmail-com.20230601.gappssmtp.com.",
                    "type": 16,
                    "TTL": 3600,
                    "data": "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KAH3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mdab8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBkLWP+LgGOgfUF4T4HZb2PY2bQtEP6QeqOtcW4rrsH24L7XhD+HSZb1hsitrE0VPbhJzxDwI4JF815XMnSVjZgYUXP8CxI1Y0FONlqtQYgsorZ9apoW1KPQe8brSSlRsi9sXB/tu56LmG7tEDNmrZ5XUwQYUUADBOu7t1niwXwIDAQAB"
                }
            ],
            "Comment": "Response from 216.239.32.10."
        }
        "#
        .to_string();
        pic.tick();
        pic.tick();
        mock_http_response(&pic, &body);
        pic.tick();
        mock_http_response(&pic, &body);

        let reply = pic.await_call(call_id).unwrap();
        match reply {
            WasmResult::Reply(data) => {
                let res: Result<SignedDkimPublicKey, String> = decode_one(&data).unwrap();
                assert!(res.is_err());
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
    }

    #[test]
    fn test_sign_gmail_invalid_selector() {
        let (pic, canister_id) = test_setup();

        // Init the signer's ethereum address.
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "init_signer_ethereum_address",
                encode_one(()).unwrap(),
            )
            .unwrap();
        let _ = pic.await_call(call_id).unwrap();

        // Submit an update call to the test canister making a canister http outcall
        // and mock a canister http outcall response.
        let selector = "20230601._domainkey.gmail.com&name=xx";
        let domain = "any.com";
        let call_id = pic
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "sign_dkim_public_key",
                Encode!(&selector, &domain).unwrap(),
            )
            .unwrap();

        let canister_http_requests = pic.get_canister_http();
        assert_eq!(canister_http_requests.len(), 0);
        let reply = pic.await_call(call_id).unwrap();
        match reply {
            WasmResult::Reply(data) => {
                let res: Result<SignedDkimPublicKey, String> = decode_one(&data).unwrap();
                assert!(res.is_err());
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
    }

    fn private_key_der_to_public_key_hex(private_key: &[u8]) -> String {
        let private_key =
            RsaPrivateKey::from_pkcs1_der(private_key).expect("Invalid format private key");
        let public_key = private_key.to_public_key();
        assert!(public_key.e() == &BigUint::from(65537u64));
        "0x".to_string() + &hex::encode(&public_key.n().to_bytes_be())
    }

    fn msg_to_hash(msg_bytes: &[u8]) -> [u8; 32] {
        const PREFIX: &str = "\x19Ethereum Signed Message:\n";
        let len = msg_bytes.len();
        let len_string = len.to_string();
        let mut eth_message = Vec::with_capacity(PREFIX.len() + len_string.len() + len);
        eth_message.extend_from_slice(PREFIX.as_bytes());
        eth_message.extend_from_slice(len_string.as_bytes());
        eth_message.extend_from_slice(msg_bytes);
        let hash = raw_keccak256(eth_message).to_vec();
        hash.try_into().unwrap()
    }

    fn test_setup() -> (PocketIc, Principal) {
        // We create a PocketIC instance consisting of the NNS, II, and one application subnet.
        let pic = PocketIcBuilder::new()
            .with_nns_subnet()
            .with_ii_subnet() // this subnet has ECDSA keys
            .with_application_subnet()
            .build();

        // We retrieve the app subnet ID from the topology.
        let topology = pic.topology();
        let app_subnet = topology.get_app_subnets()[0];

        // Create empty canisters as the anonymous principal and add cycles.
        let poseidon_canister_id = pic.create_canister_on_subnet(None, None, app_subnet);
        pic.add_cycles(poseidon_canister_id, 2_000_000_000_000);
        let dns_client_canister_id = pic.create_canister_on_subnet(None, None, app_subnet);
        pic.add_cycles(dns_client_canister_id, 2_000_000_000_000);
        // We create a canister on the app subnet.
        let canister_id = pic.create_canister_on_subnet(None, None, app_subnet);
        assert_eq!(pic.get_subnet(canister_id), Some(app_subnet));
        pic.add_cycles(canister_id, 2_000_000_000_000);
        pic.install_canister(
            poseidon_canister_id,
            include_bytes!("../../../target/wasm32-unknown-unknown/debug/poseidon.wasm").to_vec(),
            vec![],
            None,
        );
        pic.install_canister(
            dns_client_canister_id,
            include_bytes!("../../../target/wasm32-unknown-unknown/debug/dns_client.wasm").to_vec(),
            vec![],
            None,
        );
        pic.install_canister(
            canister_id,
            include_bytes!(
                "../../../target/wasm32-unknown-unknown/debug/ic_dns_oracle_backend.wasm"
            )
            .to_vec(),
            Encode!(
                &Some(Environment::Production),
                &poseidon_canister_id.to_string(),
                &dns_client_canister_id.to_string()
            )
            .unwrap(),
            None,
        );
        (pic, canister_id)
    }

    fn mock_http_response(pic: &PocketIc, body: &str) {
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
