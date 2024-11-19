use ff::PrimeField;
use hex;
use poseidon_rs::*;

// #[ic_cdk::inspect_message]
// fn inspect_message() {
//     ic_cdk::api::call::reject_message();
//     panic!("call from users is not allowed");
// }

#[ic_cdk::update]
pub fn public_key_hash(public_key_hex: String) -> Result<String, String> {
    // if !ic_cdk::api::is_controller(&ic_cdk::caller()) {
    //     return Err("only the call from the controller is allowed".to_string());
    // }
    ic_cdk::api::call::msg_cycles_accept(ic_cdk::api::call::msg_cycles_available());
    let mut public_key_n = hex::decode(&public_key_hex[2..]).map_err(|e| e.to_string())?;
    public_key_n.reverse();
    let inputs = bytes_chunk_fields(&public_key_n, 121, 2);
    let field = poseidon_fields(&inputs).map_err(|e| e.to_string())?;
    let hex = format!("{:?}", field);
    Ok(hex)
}

fn bytes_chunk_fields(bytes: &[u8], chunk_size: usize, num_chunk_in_field: usize) -> Vec<Fr> {
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
