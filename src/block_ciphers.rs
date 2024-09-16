//! # Block Ciphers Module
//! 
//! This module provides implementations of various block cipher modes of operation,
//! including Electronic Codebook (ECB), Cipher Block Chaining (CBC), Output Feedback (OFB), 
//! and Counter (CTR) modes. These modes are used to securely encrypt and decrypt data blocks using 
//! a provided encryption function (such as AES, Feistel cipher, etc.). 
//! 
//! The modes are designed to be compatible with all the encryption and decryption primitives 
//! provided in this crate (except for `rail_fence_cipher` and `route_cipher` ones, but they will 
//! be made compatible with version 0.2.0). However, due to the difference in function definitions
//! (some encryption and decryption functions neeeding a `round` argument), one would need to 
//! provide a closure that wraps the encryption/decryption function with the required arguments
//! for the specific functions that take an extra `round` argument.
//! 
//! ## Example
//! 
//! For functions which require a `round` argument (such as `feistel_network_encrypt`):
//! 
//! ```rust
//! use cryptographic_primitives::feistel_network_encrypt;
//! use cryptographic_primitives::block_ciphers::ecb_encrypt;
//! 
//! let feistel_network_encrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
//!     // choose the number of rounds for the Feistel network. In this case, 16 rounds are used.
//!     feistel_network_encrypt(input, key, 16)
//! };
//! 
//! let plaintext = b"Hello, World!";
//! let key = 0x2b7e151628aed2a6abf7158809cf4f3c;
//! let encrypted = ecb_encrypt(plaintext, key, feistel_network_encrypt_fn).unwrap();
//! 
//! ```
//! 
//! For functions which do not require a `round` argument (such as `aes_128_encrypt`):
//! 
//! ```rust
//! use cryptographic_primitives::aes_128_encrypt;
//! use cryptographic_primitives::block_ciphers::ecb_encrypt;
//! 
//! let plaintext = b"Hello, World!";
//! let key = 0x2b7e151628aed2a6abf7158809cf4f3c;
//! let encrypted = ecb_encrypt(plaintext, key, aes_128_encrypt).unwrap();
//! 
//! ```
//! 
//! This applies to all the other encryption and decryption block cipher functions provided in this module.
//! 
//! ## Modes of Operation
//! 
//! 1. **ECB (Electronic Codebook Mode)**: 
//!    - Encrypts or decrypts each block independently. Identical plaintext blocks result in identical ciphertext blocks, 
//!    making this mode unsuitable for most use cases due to its lack of diffusion.
//!    - The ECB mode functions provided here include padding the input to ensure block alignment.
//! 
//! 2. **CBC (Cipher Block Chaining Mode)**: 
//!    - XORs each plaintext block with the previous ciphertext block before encryption. This creates diffusion, making it more secure than ECB.
//!    - The first block is XORed with an Initialization Vector (IV).
//! 
//! 3. **OFB (Output Feedback Mode)**: 
//!    - Converts a block cipher into a stream cipher by generating keystream blocks based on the encryption of an IV.
//!    - This mode does not require padding since the encryption is done on the IV/previous block, not the input directly.
//! 
//! 4. **CTR (Counter Mode)**: 
//!    - Turns a block cipher into a stream cipher by encrypting incremented counters and XORing them with the plaintext.
//!    - The counter is initialized with a nonce and incremented for each block, allowing parallel encryption.

use crate::helpers::xor_bytes;

type CryptoFn = fn(&[u8], u128) -> Result<Vec<u8>, &'static str>;

/// Encrypts data using the Electronic Codebook (ECB) mode of operation and a given encryption function.
/// 
/// # Arguments
///
/// - `input`: The plaintext to be encrypted.
/// - `key`: A 128-bit key to be used for encryption.
/// - `encrypt_fn`: A function pointer for block encryption (e.g., AES or other encryption algorithms).
/// 
/// For instructions on how to use this function with different encryption functions which require 
/// an additional `round` argument, see the module documentation.
///
/// # Returns
///
/// Returns a `Result` containing the encrypted data or an error string if encryption fails.
///
/// # Errors
///
/// * `Input must not be empty`: The input plaintext must not be empty.
/// * `Invalid key length`: The key must be 128 bits (16 bytes) long.
/// * Specific errors from the encryption function used.
///
/// # Example
///
/// ```rust
/// use cryptographic_primitives::aes_128_encrypt;
/// use cryptographic_primitives::block_ciphers::ecb_encrypt;
/// 
/// let plaintext = b"Hello, World!";
/// let key = 0x1234567890abcdef1234567890abcdef_u128;
/// let encrypted = ecb_encrypt(plaintext, key, aes_128_encrypt).unwrap();
/// ```
pub fn ecb_encrypt(input: &[u8], key: u128, encrypt_fn: CryptoFn) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Err("Input must not be empty");
    }

    // pad the input with null bytes if necessary
    let mut padded_input = input.to_vec();
    if input.len() % 16 != 0 {
        let padding = 16 - (input.len() % 16);
        padded_input.extend(vec![0; padding]);
    }

    let mut result = Vec::new();

    // encrypt each 16-byte chunk of the input
    for chunk in padded_input.chunks(16) {
        let encrypted_chunk = match encrypt_fn(chunk, key) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        result.extend(encrypted_chunk);
    }

    Ok(result)
}

/// Decrypts data using the Electronic Codebook (ECB) mode of operation and a given decryption function.
/// 
/// # Arguments
/// 
/// - `input`: The ciphertext to be decrypted.
/// - `key`: A 128-bit key to be used for decryption.
/// - `decrypt_fn`: A function pointer for block decryption (e.g., AES or other decryption algorithms).
/// 
/// For instructions on how to use this function with different decryption functions which require
/// an additional `round` argument, see the module documentation.
/// 
/// # Returns
/// 
/// Returns a `Result` containing the decrypted data or an error string if decryption fails.
/// 
/// # Errors
/// 
/// * `Input must not be empty`: The input ciphertext must not be empty.
/// * `Input length must be a multiple of 16`: The input length must be a multiple of 16 bytes.
/// * Specific errors from the decryption function used.
/// 
/// # Example
/// 
/// ```rust
/// use cryptographic_primitives::{aes_128_decrypt, aes_128_encrypt};
/// use cryptographic_primitives::block_ciphers::{ecb_encrypt, ecb_decrypt};
/// 
/// let plaintext = b"Hello, World!";
/// let key = 0x2b7e151628aed2a6abf7158809cf4f3c;
/// 
/// let encrypted = ecb_encrypt(plaintext, key, aes_128_encrypt).unwrap();
/// let decrypted = ecb_decrypt(&encrypted, key, aes_128_decrypt).unwrap();
/// 
/// assert_eq!(decrypted, plaintext);
pub fn ecb_decrypt(input: &[u8], key: u128, decrypt_fn: CryptoFn) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Err("Input must not be empty");
    }

    if input.len() % 16 != 0 {
        return Err("Input length must be a multiple of 16");
    }

    let mut result = Vec::new();

    // decrypt each 16-byte chunk of the input
    for chunk in input.chunks(16) {
        let decrypted_chunk = match decrypt_fn(chunk, key) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        result.extend(decrypted_chunk);
    }

    // remove padding
    while result.last() == Some(&0) {
        result.pop();
    }

    Ok(result)
}

/// Encrypts data using the Cipher Block Chaining (CBC) mode of operation and a given encryption function.
/// 
/// # Arguments
/// 
/// - `input`: The plaintext to be encrypted.
/// - `key`: A 128-bit key to be used for encryption.
/// - `iv`: A 16-byte Initialization Vector (IV) to be used for the first block.
/// - `encrypt_fn`: A function pointer for block encryption (e.g., AES or other encryption algorithms).
/// 
/// For instructions on how to use this function with different encryption functions which require
/// an additional `round` argument, see the module documentation.
/// 
/// # Returns
/// 
/// Returns a `Result` containing the encrypted data or an error string if encryption fails.
/// 
/// # Errors
/// 
/// * `Input must not be empty`: The input plaintext must not be empty.
/// * Specific errors from the encryption function used.
/// 
/// # Example
/// 
/// ```rust
/// use cryptographic_primitives::aes_128_encrypt;
/// use cryptographic_primitives::block_ciphers::cbc_encrypt;
/// 
/// let plaintext = b"Hello, World!";
/// let key = 0x2b7e151628aed2a6abf7158809cf4f3c;
/// let iv = [0; 16];
/// 
/// let encrypted = cbc_encrypt(plaintext, key, iv, aes_128_encrypt).unwrap();
/// ```
pub fn cbc_encrypt(input: &[u8], key: u128, iv:[u8; 16], encrypt_fn: CryptoFn) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Err("Input must not be empty");
    }

    // pad the input with null bytes if necessary
    let mut padded_input = input.to_vec();
    if input.len() % 16 != 0 {
        let padding = 16 - (input.len() % 16);
        padded_input.extend(vec![0; padding]);
    }

    let mut result = Vec::new();
    let mut prev_block = iv;

    // encrypt each 16-byte chunk of the input
    for chunk in padded_input.chunks(16) {
        let xored_chunk = match xor_bytes(chunk, &prev_block) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        let encrypted_chunk = match encrypt_fn(&xored_chunk, key) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        result.extend(encrypted_chunk.clone());
        prev_block = encrypted_chunk.as_slice().try_into().unwrap();
    }

    Ok(result)
}

/// Decrypts data using the Cipher Block Chaining (CBC) mode of operation and a given decryption function.
/// 
/// # Arguments
/// 
/// - `input`: The ciphertext to be decrypted.
/// - `key`: A 128-bit key to be used for decryption.
/// - `iv`: A 16-byte Initialization Vector (IV) to be used for the first block.
/// - `decrypt_fn`: A function pointer for block decryption (e.g., AES or other decryption algorithms).
/// 
/// For instructions on how to use this function with different decryption functions which require
/// an additional `round` argument, see the module documentation.
/// 
/// # Returns
/// 
/// Returns a `Result` containing the decrypted data or an error string if decryption fails.
/// 
/// # Errors
/// 
/// * `Input must not be empty`: The input ciphertext must not be empty.
/// * `Input length must be a multiple of 16`: The input length must be a multiple of 16 bytes.
/// * Specific errors from the decryption function used.
/// 
/// # Example
/// 
/// ```rust
/// use cryptographic_primitives::{aes_128_decrypt, aes_128_encrypt};
/// use cryptographic_primitives::block_ciphers::{cbc_encrypt, cbc_decrypt};
/// 
/// let plaintext = b"Hello, World!";
/// let key = 0x2b7e151628aed2a6abf7158809cf4f3c;
/// let iv = [0; 16];
/// 
/// let encrypted = cbc_encrypt(plaintext, key, iv, aes_128_encrypt).unwrap();
/// let decrypted = cbc_decrypt(&encrypted, key, iv, aes_128_decrypt).unwrap();
/// 
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn cbc_decrypt(input: &[u8], key: u128, iv:[u8; 16], decrypt_fn: CryptoFn) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Err("Input must not be empty");
    }

    if input.len() % 16 != 0 {
        return Err("Input length must be a multiple of 16");
    }

    let mut result = Vec::new();
    let mut prev_block = iv;

    // decrypt each 16-byte chunk of the input
    for chunk in input.chunks(16) {
        let mut decrypted_chunk = match decrypt_fn(chunk, key) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        // add null bytes to the end of the decrypted chunk if it's shorter than 16 bytes
        if decrypted_chunk.len() < 16 {
            let padding = 16 - decrypted_chunk.len();
            decrypted_chunk.extend(vec![0; padding]);
        }
        

        let xored_chunk = match xor_bytes(&decrypted_chunk, &prev_block) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        result.extend(xored_chunk.clone());
        prev_block = chunk.try_into().unwrap();
    }

    // remove padding
    while result.last() == Some(&0) {
        result.pop();
    }

    Ok(result)
}

/// Encrypts data using the Output Feedback (OFB) mode of operation and a given encryption function.
/// 
/// # Arguments
/// 
/// - `input`: The plaintext to be encrypted.
/// - `key`: A 128-bit key to be used for encryption.
/// - `iv`: A 16-byte Initialization Vector (IV) to be used for the first block.
/// - `encrypt_fn`: A function pointer for block encryption (e.g., AES or other encryption algorithms).
/// 
/// For instructions on how to use this function with different encryption functions which require
/// an additional `round` argument, see the module documentation.
/// 
/// # Returns
/// 
/// Returns a `Result` containing the encrypted data or an error string if encryption fails.
/// 
/// # Errors
/// 
/// * `Input must not be empty`: The input plaintext must not be empty.
/// * Specific errors from the encryption function used.
/// 
/// # Example
/// 
/// ```rust
/// use cryptographic_primitives::aes_128_encrypt;
/// use cryptographic_primitives::block_ciphers::ofb_encrypt;
/// 
/// let plaintext = b"Hello, World!";
/// let key = 0x2b7e151628aed2a6abf7158809cf4f3c;
/// let iv = [0; 16];
/// 
/// let encrypted = ofb_encrypt(plaintext, key, iv, aes_128_encrypt).unwrap();
/// ```
pub fn ofb_encrypt(input: &[u8], key: u128, iv:[u8; 16], encrypt_fn: CryptoFn) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Err("Input must not be empty");
    }

    // pad the input with null bytes if necessary
    let mut padded_input = input.to_vec();
    if input.len() % 16 != 0 {
        let padding = 16 - (input.len() % 16);
        padded_input.extend(vec![0; padding]);
    }

    let mut result = Vec::new();
    let mut prev_block = iv;

    // encrypt each 16-byte chunk of the input
    for chunk in padded_input.chunks(16) {
        let encrypted_block = match encrypt_fn(&prev_block, key) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        let xored_chunk = match xor_bytes(chunk, &encrypted_block) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        result.extend(xored_chunk.clone());
        prev_block = encrypted_block.as_slice().try_into().unwrap();
    }

    Ok(result)
}

/// Decrypts data using the Output Feedback (OFB) mode of operation and a given decryption function.
/// 
/// # Arguments
///     
/// - `input`: The ciphertext to be decrypted.
/// - `key`: A 128-bit key to be used for decryption.
/// - `iv`: A 16-byte Initialization Vector (IV) to be used for the first block.
/// - `encrypt_fn`: A function pointer for block encryption (e.g., AES or other encryption algorithms). Note that the encryption function is used for decryption in this mode.
/// 
/// For instructions on how to use this function with different decryption functions which require
/// an additional `round` argument, see the module documentation.
/// 
/// # Returns
/// 
/// Returns a `Result` containing the decrypted data or an error string if decryption fails.
/// 
/// # Errors
///     
/// * `Input must not be empty`: The input ciphertext must not be empty.
/// * `Input length must be a multiple of 16`: The input length must be a multiple of 16 bytes.
/// * Specific errors from the decryption function used.
/// 
/// # Example
/// 
/// ```rust
/// use cryptographic_primitives::aes_128_encrypt;
/// use cryptographic_primitives::block_ciphers::{ofb_encrypt, ofb_decrypt};
/// 
/// let plaintext = b"Hello, World!";
/// let key = 0x2b7e151628aed2a6abf7158809cf4f3c;
/// let iv = [0; 16];
/// 
/// let encrypted = ofb_encrypt(plaintext, key, iv, aes_128_encrypt).unwrap();
/// let decrypted = ofb_decrypt(&encrypted, key, iv, aes_128_encrypt).unwrap();
/// 
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn ofb_decrypt(input: &[u8], key: u128, iv:[u8; 16], enctypt_fn: CryptoFn) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Err("Input must not be empty");
    }

    if input.len() % 16 != 0 {
        return Err("Input length must be a multiple of 16");
    }

    let mut result = Vec::new();
    let mut prev_block = iv;

    // decrypt each 16-byte chunk of the input
    for chunk in input.chunks(16) {
        let encrypted_block = match enctypt_fn(&prev_block, key) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        let xored_chunk = match xor_bytes(chunk, &encrypted_block) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        result.extend(xored_chunk.clone());
        prev_block = encrypted_block.as_slice().try_into().unwrap();
    }

    // remove padding
    while result.last() == Some(&0) {
        result.pop();
    }

    Ok(result)
}

/// Encrypts data using the Counter (CTR) mode of operation and a given encryption function.
/// 
/// # Arguments
/// 
/// - `input`: The plaintext to be encrypted.
/// - `key`: A 128-bit key to be used for encryption.
/// - `nonce`: An 8-byte nonce to be used for the counter.
/// - `encrypt_fn`: A function pointer for block encryption (e.g., AES or other encryption algorithms).
/// 
/// For instructions on how to use this function with different encryption functions which require
/// an additional `round` argument, see the module documentation.
/// 
/// # Returns
/// 
/// Returns a `Result` containing the encrypted data or an error string if encryption fails.
/// 
/// # Errors
/// 
/// * `Input must not be empty`: The input plaintext must not be empty.
/// * Specific errors from the encryption function used.
/// 
/// # Example
/// 
/// ```rust
/// use cryptographic_primitives::aes_128_encrypt;
/// use cryptographic_primitives::block_ciphers::ctr_encrypt;
/// 
/// let plaintext = b"Hello, World!";
/// let key = 0x2b7e151628aed2a6abf7158809cf4f3c;
/// let nonce = [0; 8];
/// 
/// let encrypted = ctr_encrypt(plaintext, key, nonce, aes_128_encrypt).unwrap();
/// ```
pub fn ctr_encrypt(input: &[u8], key: u128, nonce: [u8; 8], encrypt_fn: CryptoFn) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Err("Input must not be empty");
    }

    // pad the input with null bytes if necessary
    let mut padded_input = input.to_vec();
    if input.len() % 16 != 0 {
        let padding = 16 - (input.len() % 16);
        padded_input.extend(vec![0; padding]);
    }

    let mut result = Vec::new();

    // encrypt each 16-byte chunk of the input
    for (i, chunk) in padded_input.chunks(16).enumerate() {
        let mut nonce_block = nonce.to_vec();
        nonce_block.extend_from_slice(&i.to_le_bytes());

        let encrypted_block = match encrypt_fn(&nonce_block, key) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        let xored_chunk = match xor_bytes(chunk, &encrypted_block) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        result.extend(xored_chunk.clone());
    }

    Ok(result)
}

/// Decrypts data using the Counter (CTR) mode of operation and a given decryption function.
/// 
/// # Arguments
/// 
/// - `input`: The ciphertext to be decrypted.
/// - `key`: A 128-bit key to be used for decryption.
/// - `nonce`: An 8-byte nonce to be used for the counter.
/// - `encrypt_fn`: A function pointer for block encryption (e.g., AES or other encryption algorithms). Note that the encryption function is used for decryption in this mode.
/// 
/// For instructions on how to use this function with different decryption functions which require
/// an additional `round` argument, see the module documentation.
/// 
/// # Returns
/// 
/// Returns a `Result` containing the decrypted data or an error string if decryption fails.
/// 
/// # Errors
/// 
/// * `Input must not be empty`: The input ciphertext must not be empty.
/// * `Input length must be a multiple of 16`: The input length must be a multiple of 16 bytes.
/// * Specific errors from the decryption function used.
/// 
/// # Example
/// 
/// ```rust
/// use cryptographic_primitives::aes_128_encrypt;
/// use cryptographic_primitives::block_ciphers::{ctr_encrypt, ctr_decrypt};
/// 
/// let plaintext = b"Hello, World!";
/// let key = 0x2b7e151628aed2a6abf7158809cf4f3c;
/// let nonce = [0; 8];
/// 
/// let encrypted = ctr_encrypt(plaintext, key, nonce, aes_128_encrypt).unwrap();
/// let decrypted = ctr_decrypt(&encrypted, key, nonce, aes_128_encrypt).unwrap();
/// 
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn ctr_decrypt(input: &[u8], key: u128, nonce: [u8; 8], encrypt_fn: CryptoFn) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Err("Input must not be empty");
    }

    if input.len() % 16 != 0 {
        return Err("Input length must be a multiple of 16");
    }

    let mut result = Vec::new();

    // decrypt each 16-byte chunk of the input
    for (i, chunk) in input.chunks(16).enumerate() {
        let mut nonce_block = nonce.to_vec();
        nonce_block.extend_from_slice(&i.to_le_bytes());

        let encrypted_block = match encrypt_fn(&nonce_block, key) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        let xored_chunk = match xor_bytes(chunk, &encrypted_block) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        result.extend(xored_chunk.clone());
    }

    // remove padding
    while result.last() == Some(&0) {
        result.pop();
    }

    Ok(result)
}