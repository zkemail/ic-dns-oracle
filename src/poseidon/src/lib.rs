use ff::PrimeField;
use hex;
use poseidon_rs::*;

// consumed cycle for public_key_hash: 17_610_659 cycles
// the consumed cycle * 1.5 is charged cycle = 26_415_989 cycles
pub const CHARGED_CYCLE: u128 = 26_415_989;

/// Computes the hash of the given public key.
///
/// # Arguments
///
/// * `public_key_hex` - A string representing the public key in hexadecimal format.
///
/// # Returns
///
/// A result containing the hashed public key as a hexadecimal string, or an error message.
#[ic_cdk::update]
pub fn public_key_hash(public_key_hex: String) -> Result<String, String> {
    let available_cycles = ic_cdk::api::call::msg_cycles_available128();
    #[cfg(not(debug_assertions))]
    {
        if available_cycles < CHARGED_CYCLE {
            return Err("Insufficient cycles".to_string());
        }
    }
    // Accept all available cycles.
    ic_cdk::api::call::msg_cycles_accept128(available_cycles);
    _public_key_hash(public_key_hex)
}

pub(crate) fn _public_key_hash(public_key_hex: String) -> Result<String, String> {
    // Decode the hexadecimal public key string into a byte array.
    let mut public_key_n = hex::decode(&public_key_hex[2..]).map_err(|e| e.to_string())?;

    // Reverse the byte array.
    public_key_n.reverse();

    // Convert the byte array into a vector of field elements.
    let inputs = _bytes_chunk_fields(&public_key_n, 121, 2);

    // Compute the Poseidon hash of the field elements.
    let field = poseidon_fields(&inputs).map_err(|e| e.to_string())?;

    // Convert the hash result into a hexadecimal string.
    let hex = format!("{:?}", field);

    // Return the hash result.
    Ok(hex)
}
/// Converts a byte array into a vector of field elements.
///
/// # Arguments
///
/// * `bytes` - A slice of bytes to be converted.
/// * `chunk_size` - The size of each chunk in bits.
/// * `num_chunk_in_field` - The number of chunks in each field element.
///
/// # Returns
///
/// A vector of field elements.
fn _bytes_chunk_fields(bytes: &[u8], chunk_size: usize, num_chunk_in_field: usize) -> Vec<Fr> {
    let bits = bytes
        .into_iter()
        .flat_map(|byte| {
            let mut bits = vec![];
            for i in 0..8 {
                bits.push((byte >> i) & 1);
            }
            bits
        })
        .collect::<Vec<_>>();
    let words = bits
        .chunks(chunk_size)
        .map(|bits| {
            let mut word = Fr::zero();
            for (i, bit) in bits.iter().enumerate() {
                if *bit == 1 {
                    word += Fr::from_u128(1u128 << i);
                }
            }
            word
        })
        .collect::<Vec<_>>();
    let fields = words
        .chunks(num_chunk_in_field)
        .map(|words| {
            let mut input = Fr::zero();
            let mut coeff = Fr::one();
            let offset = Fr::from_u128(1u128 << chunk_size);
            for (i, word) in words.iter().enumerate() {
                input += coeff * word;
                coeff *= offset;
            }
            input
        })
        .collect::<Vec<_>>();
    fields
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of k256) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// we only use the k256 crate for verifying secp256k1 signatures, and such
// signature verification does not require any randomness.
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

ic_cdk::export_candid!();

#[cfg(test)]
mod test {
    use super::*;
    use candid::{decode_one, encode_args, encode_one, Encode, Principal};
    use ic_cdk::api::call::RejectionCode;
    use pocket_ic::{
        common::rest::{
            BlobCompression, CanisterHttpHeader, CanisterHttpReply, CanisterHttpResponse,
            MockCanisterHttpResponse, RawEffectivePrincipal, SubnetKind,
        },
        update_candid, PocketIc, PocketIcBuilder, WasmResult,
    };

    const PUBLIC_KEY: &'static str = "0x9edbd2293d6192a84a7b4c5c699d31f906e8b83b09b817dbcbf4bcda3c6ca02fd2a1d99f995b360f52801f79a2d40a9d31d535da1d957c44de389920198ab996377df7a009eee7764b238b42696168d1c7ecbc7e31d69bf3fcc337549dc4f0110e070cec0b111021f0435e51db415a2940011aee0d4db4767c32a76308aae634320642d63fe2e018e81f505e13e0765bd8f6366d0b443fa41ea8eb5c5b8aebb07db82fb5e10fe1d265bd61b22b6b13454f6e1273c43c08e0917cd795cc9d25636606145cff02c48d58d0538d96ab50620b28ad9f5aa685b528f41ef1bad24a546c8bdb1707fb6ee7a2e61bbb440cd9ab6795d4c106145000c13aeeedd678b05f";
    const PUBLIC_KEY_HASH: &'static str =
        "0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788";

    #[test]
    fn test_poseidon_pure() {
        assert_eq!(
            _public_key_hash(PUBLIC_KEY.to_string()).unwrap(),
            PUBLIC_KEY_HASH.to_string()
        );
    }

    #[test]
    fn test_poseidon_canister() {
        let pic = PocketIc::new();
        // Create an empty canister as the anonymous principal and add cycles.
        let canister_id = pic.create_canister();
        pic.add_cycles(canister_id, 2_000_000_000_000);
        let wasm_bytes =
            include_bytes!("../../../target/wasm32-unknown-unknown/debug/poseidon.wasm").to_vec();
        pic.install_canister(canister_id, wasm_bytes, vec![], None);
        // let sender = pic.create_canister();
        // pic.add_cycles(sender, CHARGED_CYCLE);
        let reply = pic
            .update_call(
                canister_id,
                Principal::anonymous(),
                "public_key_hash",
                encode_one(PUBLIC_KEY.to_string()).unwrap(),
            )
            .unwrap();
        println!("{:?}", reply);
        match reply {
            WasmResult::Reply(data) => {
                let res: Result<String, String> = decode_one(&data).unwrap();
                match res {
                    Ok(hash) => assert_eq!(hash, PUBLIC_KEY_HASH),
                    Err(msg) => panic!("Unexpected error {}", msg),
                }
            }
            WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
        };
    }

    // #[test]
    // fn test_poseidon_canister_insufficient_cycle() {
    //     let pic = PocketIc::new();
    //     // Create an empty canister as the anonymous principal and add cycles.
    //     let canister_id = pic.create_canister();
    //     pic.add_cycles(canister_id, 2_000_000_000_000);
    //     let wasm_bytes =
    //         include_bytes!("../../../target/wasm32-unknown-unknown/release/poseidon.wasm").to_vec();
    //     pic.install_canister(canister_id, wasm_bytes, vec![], None);
    //     let sender = pic.create_canister();
    //     pic.add_cycles(sender, CHARGED_CYCLE - 1);
    //     let reply = pic
    //         .update_call(
    //             canister_id,
    //             sender,
    //             "public_key_hash",
    //             encode_one(PUBLIC_KEY.to_string()).unwrap(),
    //         )
    //         .unwrap();
    //     println!("{:?}", reply);
    //     match reply {
    //         WasmResult::Reply(data) => {
    //             let res: Result<String, String> = decode_one(&data).unwrap();
    //             assert!(res.is_err());
    //             // assert_eq!(res.unwrap(), PUBLIC_KEY_HASH);
    //         }
    //         WasmResult::Reject(msg) => panic!("Unexpected reject {}", msg),
    //     };
    // }
}
