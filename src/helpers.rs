//! # Helpers Module
//!
//! This module contains various helper functions used across different cryptographic primitives.
//! These functions include bitwise rotations, AES S-box initialization, Feistel round functions, 
//! and more.

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
/// # Examples
/// 
/// ```
/// use cryptographic_primitives::helpers::rotl8;
/// 
/// let result = rotl8(0b10110010, 3);
/// assert_eq!(result, 0b10010101);
/// ```
pub fn rotl8(x: u8, shift: u8) -> u8 {
    (x << shift) | (x >> (8 - shift))
}

/// Initializes the AES S-box with a predefined affine transformation.
/// 
/// # Arguments
/// 
/// * `sbox` - A mutable reference to an array of 256 `u8` values where the S-box will be stored.
/// 
/// # Examples
/// 
/// ```
/// use cryptographic_primitives::helpers::initialize_aes_sbox;
/// 
/// let mut sbox = [0u8; 256];
/// initialize_aes_sbox(&mut sbox);
/// ```
pub fn initialize_aes_sbox(sbox: &mut [u8; 256]) {
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
        let xformed = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);

        sbox[p as usize] = xformed ^ 0x63;

        if p == 1 {
            break;
        }
    }

    // 0 is a special case since it has no inverse
    sbox[0] = 0x63;
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
/// # Examples
/// 
/// ```
/// use cryptographic_primitives::helpers::permute;
/// 
/// let input = vec![0u8; 16];
/// let permuted = permute(&input, false).unwrap();
/// ```
pub fn permute(input: &[u8], reverse: bool) -> Result<Vec<u8>, &'static str> {
    let input_bits = input.view_bits::<Msb0>();
    let mut permuted_bits: Vec<bool> = vec![false; 128];

    for i in 0..input_bits.len() {
        if !reverse {
            permuted_bits[P_BOX[i] as usize] = input_bits[i];
        } else {
            permuted_bits[i] = input_bits[P_BOX[i] as usize];
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
            Err(_) => panic!("HMAC creation failed"),
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
