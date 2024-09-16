//! # Helpers Module
//!
//! This module provides utility functions used throughout the cryptographic primitives.
//! It includes functions for performing bitwise operations (like rotations), AES S-box
//! initialization, Feistel round operations, and functions to facilitate common cryptographic tasks
//! like XORing byte arrays or permuting bits.
//!
//! These helper functions are designed to be reusable across various cryptographic algorithms and modes
//! implemented within this crate, contributing to the overall encryption, decryption, and key generation processes.
//!
//! Key functionality provided by this module includes:
//! - Bitwise rotation of bytes (e.g., `rotl8`)
//! - Initialization of the AES S-box used in AES encryption/decryption
//! - Feistel round function with HMAC-SHA256
//! - Key derivation using HMAC-SHA256
//! - Byte-level XOR operations and P-box bit permutations
//! - AES MixColumns and inverse MixColumns operations

use hmac::{Hmac, Mac};
use sha2::Sha256;
use bitvec::prelude::*;
use crate::constants::*;

/// Rotates an 8-bit unsigned integer to the left by a specified number of bits.
/// 
/// # Arguments
/// 
/// * `x` - The 8-bit unsigned integer to rotate.
/// * `shift` - The number of bits to rotate to the left.
/// 
/// # Returns
/// 
/// A new 8-bit unsigned integer that is the result of rotating `x` to the left by `shift` bits.
/// 
/// # Errors
/// 
/// * `Shift value must be between 0 and 7` - If the shift value is not between 0 and 7.
/// 
/// # Examples
/// 
/// ```
/// use cryptographic_primitives::helpers::rotl8;
/// 
/// let result = rotl8(0b10110010, 3).unwrap();
/// assert_eq!(result, 0b10010101);
/// ```
pub fn rotl8(x: u8, shift: u8) -> Result<u8, &'static str> {
    if shift >= 8 {
        return Err("Shift value must be between 0 and 7");
    }
    if shift == 0 {
        return Ok(x);
    }

    Ok((x << shift) | (x >> (8 - shift)))
}

/// Initializes the AES S-box with a predefined affine transformation.
/// 
/// # Arguments
/// 
/// * `sbox` - A mutable reference to an array of 256 `u8` values where the S-box will be stored.
/// 
/// # Returns
/// 
/// A `Result` containing `()` on success, or an error message on failure.
/// 
/// # Errors
/// 
/// Can return an error message if the affine transformation fails (specific to the `rotl8` function).
/// 
/// # Examples
/// 
/// ```
/// use cryptographic_primitives::helpers::initialize_aes_sbox;
/// 
/// let mut sbox = [0u8; 256];
/// initialize_aes_sbox(&mut sbox);
/// ```
pub fn initialize_aes_sbox(sbox: &mut [u8; 256]) -> Result<(), &'static str> {
    let mut p: u8 = 1;
    let mut q: u8 = 1;

    loop {
        // multiply p by 3
        p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1B } else { 0 };

        // divide q by 3 (equals multiplication by 0xf6)
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= if q & 0x80 != 0 { 0x09 } else { 0 };

        // compute the affine transformation
        let xformed = q 
            ^ rotl8(q, 1)? 
            ^ rotl8(q, 2)? 
            ^ rotl8(q, 3)? 
            ^ rotl8(q, 4)?;

        sbox[p as usize] = xformed ^ 0x63;

        if p == 1 {
            break;
        }
    }

    // 0 is a special case since it has no inverse
    sbox[0] = 0x63;

    Ok(())
}

/// Permutes a block of 128 bits using the P-box.
/// 
/// # Arguments
/// 
/// * `input` - The input byte slice to permute.
/// * `reverse` - A boolean indicating whether to reverse the permutation.
/// 
/// # Returns
/// 
/// A `Result` containing the permuted byte vector on success, or an error message on failure.
/// 
/// # Errors
/// 
/// * `Input length must be 16 bytes` - If the input length is not 16 bytes.
/// 
/// # Examples
/// 
/// ```
/// use cryptographic_primitives::helpers::permute;
/// use cryptographic_primitives::constants::P_BOX;
/// 
/// let input = vec![0u8; 16];
/// let permuted = permute(&input, false, &P_BOX).unwrap();
/// ```
pub fn permute(input: &[u8], reverse: bool, p_box: &[u8; 128]) -> Result<Vec<u8>, &'static str> {
    if input.len() != 16 {
        return Err("Input length must be 16 bytes");
    }

    let input_bits = input.view_bits::<Msb0>();
    let mut permuted_bits: Vec<bool> = vec![false; 128];

    for i in 0..input_bits.len() {
        if !reverse {
            permuted_bits[p_box[i] as usize] = input_bits[i];
        } else {
            permuted_bits[i] = input_bits[p_box[i] as usize];
        }
    }

    // convert the bit vector to a byte vector
    let mut result = Vec::with_capacity(16);
    for i in 0..16 {
        let mut byte = 0;
        for j in 0..8 {
            byte |= (permuted_bits[i * 8 + j] as u8) << (7 - j);
        }
        result.push(byte);
    }

    Ok(result)
}

/// Performs a Feistel round function using HMAC-SHA256.
/// 
/// # Arguments
/// 
/// * `input` - The input byte slice for the round function.
/// * `subkey` - The subkey to use in the HMAC.
/// 
/// # Returns
/// 
/// A `Result` containing the resulting byte vector on success, or an error message on failure.
/// 
/// # Errors
/// 
/// * `HMAC creation failed` - If the HMAC creation fails.
/// 
/// # Examples
/// 
/// ```
/// use cryptographic_primitives::helpers::feistel_round_function;
/// 
/// let input = b"data";
/// let subkey = b"key";
/// let result = feistel_round_function(input, subkey).unwrap();
/// ```
pub fn feistel_round_function(input: &[u8], subkey: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut mac = match Hmac::<Sha256>::new_from_slice(subkey) {
        Ok(m) => m,
        Err(_) => panic!("HMAC creation failed"),
    };

    mac.update(input);

    Ok(mac.finalize().into_bytes().to_vec())
}

/// Key Derivation Function (KDF) that generates a series of subkeys from an initial key using HMAC-SHA256.
/// 
/// # Arguments
/// 
/// * `initial_key` - The initial key as a byte slice.
/// * `num_rounds` - The number of subkeys to generate.
/// 
/// # Returns
/// 
/// A `Result` containing a vector of subkey vectors on success, or an error message on failure.
/// 
/// # Errors
/// 
/// * `HMAC creation failed` - If the HMAC creation fails.
/// 
/// # Examples
/// 
/// ```
/// use cryptographic_primitives::helpers::kdf;
/// 
/// let initial_key = b"initial_key";
/// let subkeys = kdf(initial_key, 10).unwrap();
/// ```
pub fn kdf(initial_key: &[u8], num_rounds: usize) -> Result<Vec<Vec<u8>>, &'static str> { 
    let mut subkeys = Vec::with_capacity(num_rounds);
    let mut key = initial_key.to_vec();

    for _ in 0..num_rounds {
        // Use HMAC-SHA256 as the PRF
        let mac = match Hmac::<Sha256>::new_from_slice(&key) {
            Ok(m) => m,
            Err(_) => return Err("HMAC creation failed"),
        };

        // Generate subkey
        let subkey = mac.finalize().into_bytes().to_vec();

        // Update the key for the next round
        key = subkey.clone();

        subkeys.push(subkey);
    }
    Ok(subkeys)
}

/// Mixes a column of 4 bytes in the AES mix columns step.
/// 
/// # Arguments
/// 
/// * `r` - A mutable reference to an array of 4 bytes representing the column to mix.
/// 
/// # Examples
/// 
/// ```
/// use cryptographic_primitives::helpers::gmix_column;
/// 
/// let mut column = [0x87, 0x6E, 0x46, 0xA6];
/// gmix_column(&mut column);
/// ```
pub fn gmix_column(r: &mut [u8; 4]) {
    let mut a = [0u8; 4];
    let mut b = [0u8; 4];
    let mut h: u8;

    for c in 0..4 {
        a[c] = r[c];
        h = r[c] >> 7; // logical right shift
        b[c] = r[c] << 1;
        b[c] ^= h * 0x1B; // Rijndael's Galois field
    }

    r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; // 2 * a0 + a3 + a2 + 3 * a1
    r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; // 2 * a1 + a0 + a3 + 3 * a2
    r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; // 2 * a2 + a1 + a0 + 3 * a3
    r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; // 2 * a3 + a2 + a1 + 3 * a0
}

/// Inversely mixes a column of 4 bytes in the AES inverse mix columns step.
/// 
/// # Arguments
/// 
/// * `r` - A mutable reference to an array of 4 bytes representing the column to mix inversely.
/// 
/// # Examples
/// 
/// ```
/// use cryptographic_primitives::helpers::gmix_column_inv;
/// 
/// let mut column = [0x87, 0x6E, 0x46, 0xA6];
/// gmix_column_inv(&mut column);
/// ```
pub fn gmix_column_inv(r: &mut [u8; 4]) {
    let a = r.clone();

    r[0] = MIX_COLUMNS_LOOKUP_14[a[0] as usize] ^ 
           MIX_COLUMNS_LOOKUP_11[a[1] as usize] ^ 
           MIX_COLUMNS_LOOKUP_13[a[2] as usize] ^ 
           MIX_COLUMNS_LOOKUP_9[a[3] as usize];
    
    r[1] = MIX_COLUMNS_LOOKUP_9[a[0] as usize] ^ 
           MIX_COLUMNS_LOOKUP_14[a[1] as usize] ^ 
           MIX_COLUMNS_LOOKUP_11[a[2] as usize] ^ 
           MIX_COLUMNS_LOOKUP_13[a[3] as usize];

    r[2] = MIX_COLUMNS_LOOKUP_13[a[0] as usize] ^
           MIX_COLUMNS_LOOKUP_9[a[1] as usize] ^ 
           MIX_COLUMNS_LOOKUP_14[a[2] as usize] ^ 
           MIX_COLUMNS_LOOKUP_11[a[3] as usize];

    r[3] = MIX_COLUMNS_LOOKUP_11[a[0] as usize] ^
           MIX_COLUMNS_LOOKUP_13[a[1] as usize] ^ 
           MIX_COLUMNS_LOOKUP_9[a[2] as usize] ^ 
           MIX_COLUMNS_LOOKUP_14[a[3] as usize];
}

/// XORs two byte slices together.
/// 
/// # Arguments
/// 
/// * `input` - The input byte slice to XOR.
/// * `key` - The key byte slice to XOR.
/// 
/// # Returns
/// 
/// A `Result` containing the resulting byte vector on success, or an error message on failure.
/// 
/// # Errors
/// 
/// * `Input and key lengths must be equal` - If the input and key lengths are not equal.
/// 
/// # Examples
/// 
/// ```
/// use cryptographic_primitives::helpers::xor_bytes;
/// 
/// let input = [0xFF, 0xAA, 0x55, 0x00];
/// let key = [0x00, 0xFF, 0xAA, 0x55];
/// let expected_output = [0xFF, 0x55, 0xFF, 0x55];
/// let result = xor_bytes(&input, &key).unwrap();
/// assert_eq!(result, expected_output);
/// ```
pub fn xor_bytes(input: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
    if input.len() != key.len() {
        return Err("Input and key lengths must be equal");
    }

    let mut result = Vec::with_capacity(input.len());
    for i in 0..input.len() {
        result.push(input[i] ^ key[i]);
    }

    Ok(result)
}