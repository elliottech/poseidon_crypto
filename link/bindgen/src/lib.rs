extern crate circuit;
extern crate plonky2;

use circuit::eddsa::curve::scalar_field::ECgFp5Scalar;
use circuit::poseidon2::hash::Poseidon2Hash;
use circuit::poseidon2::hash::Poseidon2Permutation;
use circuit::types::config::{const_f, F};
use plonky2::field::extension::quintic::QuinticExtension;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::plonk::config::Hasher;
use std::slice;

#[no_mangle]
pub extern "C" fn hash_n_to_hash_no_pad(data: *const u64, len: usize, dst: *mut u64) {
    if data.is_null() || dst.is_null() {
        return;
    }

    let output_slice = unsafe { slice::from_raw_parts_mut(dst, 4) };
    for (i, &value) in plonky2::hash::hashing::hash_n_to_hash_no_pad::<F, Poseidon2Permutation<F>>(
        &unsafe { slice::from_raw_parts(data, len) }
            .iter()
            .map(|&x| const_f(x))
            .collect::<Vec<F>>(),
    )
    .elements
    .iter()
    .enumerate()
    {
        output_slice[i] = value.to_canonical_u64();
    }
}

#[no_mangle]
pub extern "C" fn hash_no_pad(input: *const u64, input_len: usize, dst: *mut u64) {
    if input.is_null() || dst.is_null() {
        return;
    }

    let output_slice = unsafe { slice::from_raw_parts_mut(dst, 4) };
    for (i, &value) in Poseidon2Hash::hash_no_pad(
        &unsafe { slice::from_raw_parts(input, input_len) }
            .iter()
            .map(|&x| F::from_canonical_u64(x))
            .collect::<Vec<F>>(),
    )
    .elements
    .iter()
    .enumerate()
    {
        output_slice[i] = value.to_canonical_u64();
    }
}

#[no_mangle]
pub extern "C" fn schnorr_sign_hashed_message(m_hashed: *const u64, sk: *const u64, sig: *mut u64) {
    if m_hashed.is_null() || sk.is_null() || sig.is_null() {
        return;
    }

    let m_hashed_slice = unsafe { slice::from_raw_parts(m_hashed, 5) };
    let sk_slice = unsafe { slice::from_raw_parts(sk, 5) };
    let sig_slice = unsafe { slice::from_raw_parts_mut(sig, 10) };

    let hashed_message = QuinticExtension([
        F::from_canonical_u64(m_hashed_slice[0]),
        F::from_canonical_u64(m_hashed_slice[1]),
        F::from_canonical_u64(m_hashed_slice[2]),
        F::from_canonical_u64(m_hashed_slice[3]),
        F::from_canonical_u64(m_hashed_slice[4]),
    ]);
    let sk = ECgFp5Scalar([
        sk_slice[0],
        sk_slice[1],
        sk_slice[2],
        sk_slice[3],
        sk_slice[4],
    ]);
    let schnorr_sig = circuit::eddsa::schnorr::schnorr_sign_hashed_message(&hashed_message, &sk);
    for i in 0..5 {
        sig_slice[i] = schnorr_sig.s.0[i];
        sig_slice[i + 5] = schnorr_sig.e.0[i];
    }

    // Foreign libraries often hand off ownership of resources to the calling code.
    // When this occurs, we must use Rust's destructors to provide safety and guarantee
    // the release of these resources (especially in the case of panic).
    drop(schnorr_sig);
}

#[no_mangle]
pub extern "C" fn hash_to_quintic_extension(input: *const u64, input_len: usize, dst: *mut u64) {
    if input.is_null() || dst.is_null() {
        return;
    }

    let input_slice = unsafe { slice::from_raw_parts(input, input_len) };
    let dst_slice = unsafe { slice::from_raw_parts_mut(dst, 5) };

    let result = circuit::eddsa::schnorr::hash_to_quintic_extension(
        &input_slice
            .iter()
            .map(|&x| F::from_canonical_u64(x))
            .collect::<Vec<_>>(),
    );

    for i in 0..5 {
        dst_slice[i] = result.0[i].to_canonical_u64();
    }
}

#[no_mangle]
pub extern "C" fn schnorr_pk_from_sk(input: *const u64, dst: *mut u64) {
    if input.is_null() || dst.is_null() {
        return;
    }

    let input_slice = unsafe { slice::from_raw_parts(input, 5) };
    let dst_slice = unsafe { slice::from_raw_parts_mut(dst, 5) };

    circuit::eddsa::schnorr::schnorr_pk_from_sk(&ECgFp5Scalar([
        input_slice[0],
        input_slice[1],
        input_slice[2],
        input_slice[3],
        input_slice[4],
    ]))
    .0
    .iter()
    .enumerate()
    .for_each(|(i, &x)| dst_slice[i] = x.to_canonical_u64());
}
