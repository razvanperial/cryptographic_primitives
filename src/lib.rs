//! # cryptograhpic_primitives
//! 'cryptograhpic_primitives' is a crate that provides implementations of various cryptographic primitives.

pub mod constants;
pub mod helpers;

use crate::constants::*;
use crate::helpers::*;

/// Encrypts a string using the rail fence cipher.
/// 
/// # Arguments
/// 
/// * `input` - The string to encrypt
/// * `key` - The number of rails to use
/// 
/// # Example
/// 
/// ```
/// use cryptographic_primitives::rail_fence_cipher_encrypt;
/// 
/// let plaintext = String::from("Hello, world!");
/// let ciphertext = rail_fence_cipher_encrypt(&plaintext, 4).unwrap();
/// 
/// assert_eq!(ciphertext, "H !e,wdloollr");
/// ```
/// 
/// # Errors
/// 
/// * `Input must not be empty` - If the input string is empty
/// * `Key must be greater than 0` - If the key is less than 1
/// * `Error in fence creation` - If there is an error in the fence creation
pub fn rail_fence_cipher_encrypt(input: &str, key: u128) -> Result<String, &'static str> {

    if input.is_empty() {
        return Err("Input must not be empty");
    } else if key == 1 || key >= input.len() as u128 {
        return Ok(String::from(input));
    } else if key < 1{
        return Err("Key must be greater than 0");
    }

    let row_length = (input.len() / key as usize) * 2 - 1 ;
    let mut fence: Vec<Vec<char>> = vec![vec!['\0'; row_length]; key as usize];
    let mut rail: i32 = 0;
    let mut dir: i32 = 1; // 1 = down, -1 = up
    let mut result = String::new();
    result.reserve_exact(input.len());

    for c in input.chars() {
        let column_index = match fence[rail as usize].iter().position(|&x| x == '\0') {
            Some(i) => i,
            None => return Err("Error in fence creation"),
        };

        fence[rail as usize][column_index] = c;

        rail += dir;
        if rail == 0 || rail == key as i32 - 1 {
            dir = -dir;
        }
    }

    for rail in fence {
        for c in rail {
            if c != '\0' {
                result.push(c);
            }
        }
    }

    Ok(result)
}

/// Decrypts a string using the rail fence cipher.
/// 
/// # Arguments
/// 
/// * `input` - The string to decrypt
/// * `key` - The number of rails used to encrypt the string
/// 
/// # Example
/// 
/// ```
/// use cryptographic_primitives::rail_fence_cipher_decrypt;
/// 
/// let ciphertext = String::from("H !e,wdloollr");
/// let plaintext = rail_fence_cipher_decrypt(&ciphertext, 4).unwrap();
/// 
/// assert_eq!(plaintext, "Hello, world!");
/// ```
/// 
/// # Errors
/// 
/// * `Input must not be empty` - If the input string is empty
/// * `Key must be greater than 0` - If the key is less than 1
/// * `Error in fence creation` - If there is an error in the fence creation
pub fn rail_fence_cipher_decrypt(input: &str, key: u128) -> Result<String, &'static str> {

    if input.is_empty() {
        return Err("Input must not be empty");
    } else if key == 1 || key >= input.len() as u128 {
        return Ok(String::from(input));
    } else if key < 1{
        return Err("Key must be greater than 0");
    }

    let mut fence = vec![vec!['\0'; input.len()]; key as usize];
    let mut dir = 1;
    let mut row: i32 = 0;
    let mut column: i32 = 0;
    let mut index;
    let mut result = String::new();
    result.reserve_exact(input.len());

    for _ in 0..input.len() {
        fence[row as usize][column as usize] = '*';
        column += 1;

        row += dir;
        if row == 0 || row == key as i32 - 1 {
            dir = -dir;
        }
    }

    index = 0;

    for i in 0..key as usize {
        for j in 0..input.len() {
            if fence[i][j] == '*' && index < input.len() {
                fence[i][j] = match input.chars().nth(index) {
                    Some(c) => c,
                    None => return Err("Error in fence creation"),
                };
                index += 1;
            }
        }
    }

    row = 0;
    column = 0;
    dir = 1;

    for _ in 0..input.len() {
        result.push(fence[row as usize][column as usize]);
        column += 1;

        row += dir;
        if row == 0 || row == key as i32 - 1 {
            dir = -dir;
        }
    }
    
    Ok(result)
}

/// Encrypts a string using the route cipher.
/// 
/// # Arguments
/// 
/// * `input` - The string to encrypt
/// * `key` - The number of rails to use
/// 
/// # Example
/// 
/// ```
/// use cryptographic_primitives::route_cipher_encrypt;
/// 
/// let plaintext = String::from("Hello, world!");
/// let ciphertext = route_cipher_encrypt(&plaintext, 3).unwrap();
/// 
/// assert_eq!(ciphertext, "Hl r!eowl l,od ");
/// 
/// ```
/// 
/// # Errors
/// 
/// * `Input must not be empty` - If the input string is empty  
/// * `Key must be greater than 0` - If the key is less than 1
/// * `Memory access error` - If there is an error in setting the characters in the result string
pub fn route_cipher_encrypt(input: &str, key: u128) -> Result<String, &'static str> {

    if input.is_empty() {
        return Err("Input must not be empty");
    } else if key == 1 || key >= input.len() as u128 {
        return Ok(String::from(input));
    } else if key < 1{
        return Err("Key must be greater than 0");
    }

    let mut result = String::new();
    let result_size = input.len() + (key as usize - input.len() % key as usize);
    let row_size = result_size / key as usize;

    result.reserve(result_size);

    for i in 0..result_size {
        let index = (i / row_size) + key as usize * (i % row_size);
        if index < input.len() {
            match input.chars().nth(index) {
                Some(c) => result.push(c),
                None => return Err("Memory access error"),
            }
        } else {
            result.push(' ');
        }
    }

    Ok(String::from(result))
}

/// Decrypts a string using the route cipher.
/// 
/// # Arguments
/// 
/// * `input` - The string to decrypt
/// * `key` - The number of rails used to encrypt the string
/// 
/// # Example
/// 
/// ```
/// use cryptographic_primitives::route_cipher_decrypt;
/// 
/// let ciphertext = String::from("Hl r!eowl l,od ");
/// let plaintext = route_cipher_decrypt(&ciphertext, 3).unwrap();
/// 
/// assert_eq!(plaintext, "Hello, world!");
/// 
/// ```
/// 
/// # Errors
/// 
/// * `Input must not be empty` - If the input string is empty
/// * `Key must be greater than 0` - If the key is less than 1
/// * `Memory access error` - If there is an error in setting the characters in the result string
pub fn route_cipher_decrypt(input: &str, key: u128) -> Result<String, &'static str> {
    
    if input.is_empty() {
        return Err("Input must not be empty");
    } else if key == 1 || key >= input.len() as u128 {
        return Ok(String::from(input));
    } else if key < 1{
        return Err("Key must be greater than 0");
    }

    let mut result = String::new();
    result.reserve(input.len());
    let row_size = input.len() / key as usize;

    for i in 0..input.len() {
        let index;
        if i == input.len() - 1 {
            index = input.len() - 1;
        } else {
            index = (i * row_size) % (input.len() - 1);
        }
        match input.chars().nth(index) {
            Some(c) => result.push(c),
            None => return Err("Memory access error"),
        }
    }

    // cut off trailing spaces
    result = result.trim_end().to_string();

    Ok(String::from(result))
}

/// Encrypts an array of bytes using the feistel cipher
/// 
/// # Arguments
/// 
/// * `input` - The array of bytes to encrypt
/// * `key` - The key to use for encryption
/// * `rounds` - The number of rounds to use for encryption
/// 
/// # Example
/// 
/// ```
///  use cryptographic_primitives::feistel_network_encrypt;
/// 
/// let plaintext = b"Hello, world!";
/// let ciphertext = feistel_network_encrypt(plaintext, &15, 5).unwrap();
/// 
/// assert_eq!(ciphertext, vec![20, 214, 205, 97, 45, 140, 194, 245, 186, 32, 98, 214, 120, 45]);
/// 
/// ```
/// 
/// # Errors
/// 
/// * `Input must not be empty` - If the input array is empty
/// * `Number of rounds must be greater than 0` - If the number of rounds is less than 1
/// * `HMAC creation failed` - If there is an error in creating the HMAC for the round function or the Key Derivation Function
pub fn feistel_network_encrypt(input: &[u8], key: &u128, rounds: u32) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Err("Input must not be empty");
    } else if rounds < 1 {
        return Err("Number of rounds must be greater than 0");
    }

    let subkeys = kdf(&key.to_le_bytes(), rounds as usize).unwrap();
    
    let mut padded_input = input.to_vec();
    if input.len() % 2 != 0 {
        // Pad the input with a null byte
        padded_input = input.to_vec();
        padded_input.push(0);
    }

    let input_size = padded_input.len();
    let mut left_side = padded_input[..input_size / 2].to_vec();
    let mut right_side = padded_input[input_size / 2..].to_vec();

    for i in 0..rounds {
        let mut round_result = Vec::with_capacity(input_size);
        let round_function_result = feistel_round_function(&right_side, &subkeys[i as usize]).unwrap();
        for j in 0..input_size / 2 {
            round_result.push(left_side[j] ^ round_function_result[j]);
        }
        left_side = right_side;
        right_side = round_result;
    }

    let mut result = Vec::with_capacity(input_size);
    result.append(&mut right_side);
    result.append(&mut left_side);

    Ok(result)
}

/// Decrypts an array of bytes using the feistel cipher
/// 
/// # Arguments
/// 
/// * `input` - The array of bytes to decrypt
/// * `key` - The key to use for decryption
/// * `rounds` - The number of rounds to use for decryption
/// 
/// # Example
/// 
/// ```
/// use cryptographic_primitives::{feistel_network_encrypt, feistel_network_decrypt};
/// 
/// let plaintext = b"Hello, world!";
/// let ciphertext = feistel_network_encrypt(plaintext, &15, 5).unwrap();
/// let decrypted = feistel_network_decrypt(&ciphertext, &15, 5).unwrap();
/// 
/// assert_eq!(decrypted, plaintext.to_vec());
/// 
/// ```
/// 
/// # Errors
/// 
/// * `Input must not be empty` - If the input array is empty
/// * `Number of rounds must be greater than 0` - If the number of rounds is less than 1
/// * `HMAC creation failed` - If there is an error in creating the HMAC for the round function or the Key Derivation Function
pub fn feistel_network_decrypt(input: &[u8], key: &u128, rounds: u32) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Err("Input must not be empty");
    } else if rounds < 1 {
        return Err("Number of rounds must be greater than 0");
    }

    let subkeys = kdf(&key.to_le_bytes(), rounds as usize).unwrap();

    let mut padded_input = input.to_vec();
    if input.len() % 2 != 0 {
        // Pad the input with a null byte
        padded_input = input.to_vec();
        padded_input.push(0);
    }

    let input_size = padded_input.len();
    let mut left_side = padded_input[..input_size / 2].to_vec();
    let mut right_side = padded_input[input_size / 2..].to_vec();

    for i in (0..rounds).rev() {
        let mut round_result = Vec::with_capacity(input_size);
        let round_function_result = feistel_round_function(&right_side, &subkeys[i as usize]).unwrap();
        for j in 0..input_size / 2 {
            round_result.push(left_side[j] ^ round_function_result[j]);
        }
        left_side = right_side;
        right_side = round_result;
    }

    let mut result = Vec::with_capacity(input_size);
    result.append(&mut right_side);
    result.append(&mut left_side);

    if result[input_size - 1] == 0 {
        result.pop();
    }

    Ok(result)
}

/// Encrypts an array of bytes using the substitution-permutation network
/// 
/// # Arguments
/// 
/// * `input` - The array of bytes to encrypt
/// * `key` - The key to use for encryption
/// * `rounds` - The number of rounds to use for encryption
/// 
/// # Example
/// 
/// ```
/// use cryptographic_primitives::sub_per_box_encrypt;
/// 
/// let plaintext = b"Hello, world!";
/// let ciphertext = sub_per_box_encrypt(plaintext, 15, 3).unwrap();
/// 
/// assert_eq!(ciphertext, vec![88, 16, 91, 161, 233, 130, 28, 216, 159, 37, 150, 29, 125, 37, 247, 49]);
/// 
/// ```
/// 
/// # Errors
/// 
/// * `Input must not be empty` - If the input array is empty
/// * `Number of rounds must be greater than 0` - If the number of rounds is less than 1
pub fn sub_per_box_encrypt(input: &[u8], key: u128, rounds: u32) -> Result<Vec<u8>, &'static str> {

    if input.is_empty() {
        return Err("Input must not be empty");
    } else if rounds < 1 {
        return Err("Number of rounds must be greater than 0");
    }

    // pad the input with null bytes if necessary
    let mut padded_input = input.to_vec();
    if input.len() % 16 != 0 {
        let padding = 16 - input.len() % 16;
        for _ in 0..padding {
            padded_input.push(0);
        }
    }

    let input_size = padded_input.len();
    let mut subkeys = kdf(&key.to_le_bytes(), (rounds / 2 + 1) as usize).unwrap();
    let mut result = padded_input;

    // split each subkey in half to generate 128-bit subkeys
    for i in 0..subkeys.len() {
        let mut subkey1 = subkeys[i].to_vec();
        let subkey2 = subkey1.split_off(16);
        subkeys[i] = subkey1;
        subkeys.push(subkey2);
    }

    subkeys.truncate(rounds as usize + 1);

    for i in 0..rounds {
        // go over each 128-bit block of input
        for j in (0..input_size).step_by(16) {
            // XOR with the subkey
            for l in 0..16 {
                result[j + l] ^= subkeys[i as usize][l];
            }

            // Substitute the bytes
            for l in 0..16 {
                result[j + l] = S_BOX[result[j + l] as usize];
            }

            // In the last round, the permutation is replaced by another key step
            if i == rounds - 1 {
                for l in 0..16 {
                    result[j + l] ^= subkeys[(i + 1) as usize][l];
                }
            } else {
                // Permute the bits
                let permuted_sequence = permute(&result[j..j + 16], false).unwrap();
                for l in 0..16 {
                    result[j + l] = permuted_sequence[l];
                }
            }
        }
    }

    Ok(result)
}

/// Decrypts an array of bytes using the substitution-permutation network
/// 
/// # Arguments
/// 
/// * `input` - The array of bytes to decrypt
/// * `key` - The key to use for decryption
/// * `rounds` - The number of rounds to use for decryption
/// 
/// # Example
/// 
/// ```
/// use cryptographic_primitives::{sub_per_box_encrypt, sub_per_box_decrypt};
/// 
/// let plaintext = b"Hello, world!";
/// let ciphertext = sub_per_box_encrypt(plaintext, 15, 3).unwrap();
/// let decrypted = sub_per_box_decrypt(&ciphertext, 15, 3).unwrap();
/// 
/// assert_eq!(decrypted, plaintext.to_vec());
/// ```
/// 
/// # Errors
/// 
/// * `Input must not be empty` - If the input array is empty
/// * `Number of rounds must be greater than 0` - If the number of rounds is less than 1
pub fn sub_per_box_decrypt(input: &[u8], key: u128, rounds: u32) -> Result<Vec<u8>, &'static str> {

    if input.is_empty() {
        return Err("Input must not be empty");
    } else if rounds < 1 {
        return Err("Number of rounds must be greater than 0");
    }

    let input_size = input.len();
    let mut subkeys = kdf(&key.to_le_bytes(), (rounds / 2 + 1) as usize).unwrap();
    let mut result = input.to_vec();

    // split each subkey in half to generate 128-bit subkeys
    for i in 0..subkeys.len() {
        let mut subkey1 = subkeys[i].to_vec();
        let subkey2 = subkey1.split_off(16);
        subkeys[i] = subkey1;
        subkeys.push(subkey2);
    }

    subkeys.truncate(rounds as usize + 1);

    for i in (0..rounds).rev() {
        // go over each 128-bit block of input
        for j in (0..input_size).step_by(16) {
            // In the last round, the permutation is replaced by another key step
            if i == rounds - 1 {
                for l in 0..16 {
                    result[j + l] ^= subkeys[(i + 1) as usize][l];
                }
            } else {
                // Permute the bits
                let permuted_sequence = permute(&result[j..j + 16], true).unwrap();
                for l in 0..16 {
                    result[j + l] = permuted_sequence[l];
                }
            }

            // Substitute the bytes
            for l in 0..16 {
                result[j + l] = S_BOX.iter().position(|&x| x == result[j + l]).unwrap() as u8;
            }

            // XOR with the subkey
            for l in 0..16 {
                result[j + l] ^= subkeys[i as usize][l];
            }
        }
    }

    // remove all trailing null bytes
    while result.last() == Some(&0) {
        result.pop();
    }

    Ok(result)
}

/// Encrypts an array of bytes using the AES-128 cipher
/// 
/// # Arguments
/// 
/// * `input` - The array of bytes to encrypt
/// * `key` - The key to use for encryption
/// 
/// # Example
/// 
/// ```
/// use cryptographic_primitives::aes_128_encrypt;
/// 
/// let plaintext = b"Hello, world!";
/// let ciphertext = aes_128_encrypt(plaintext, 15).unwrap();
/// 
/// assert_eq!(ciphertext, vec![155, 3, 38, 236, 178, 74, 170, 22, 159, 40, 200, 204, 111, 144, 70, 26]);
/// 
/// ```
/// 
/// # Errors
/// 
/// * `Input must not be empty` - If the input array is empty
pub fn aes_128_encrypt(input: &[u8], key: u128) -> Result<Vec<u8>, &'static str> {

    if input.is_empty() {
        return Err("Input must not be empty");
    }

    // pad the input with null bytes if necessary
    let mut padded_input = input.to_vec();
    if input.len() % 16 != 0 {
        let padding = 16 - input.len() % 16;
        for _ in 0..padding {
            padded_input.push(0);
        }
    }

    let input_size = padded_input.len();
    let mut subkeys = kdf(&key.to_le_bytes(), 6).unwrap();
    let mut result = padded_input;
    let mut s_box = [0u8; 256];
    initialize_aes_sbox(&mut s_box);

    // split each subkey in half to generate 128-bit subkeys
    for i in 0..subkeys.len() {
        let mut subkey1 = subkeys[i].to_vec();
        let subkey2 = subkey1.split_off(16);
        subkeys[i] = subkey1;
        subkeys.push(subkey2);
    }
    subkeys.truncate(11);

    for i in 0..10 {

        // go over each 128-bit block of input
        for j in (0..input_size).step_by(16) {

            // First XOR step
            if i == 0 {
                for l in 0..16 {
                    result[j + l] ^= subkeys[0][l];
                }
            }

            // Sub-bytes step
            for l in 0..16 {
                result[j + l] = s_box[result[j + l] as usize];
            }

            let temp_result = result[j..j + 16].to_vec();

            // Shift-rows step
            for l in 0..16 {
                result[j + l] = temp_result[(j + l + l % 4 * 4) % 16];
            }

            // Mix-columns step
            if i < 9 { // skip this step in the last round
                for l in (0..16).step_by(4) {
                    let mut column = [0u8; 4];
                    for k in 0..4 {
                        column[k] = result[j + l + k];
                    }
                    gmix_column(&mut column);
                    for k in 0..4 {
                        result[j + l + k] = column[k];
                    }
                }
            }

            // Add round key
            for l in 0..16 {
                result[j + l] ^= subkeys[i as usize + 1][l];
            }

        }
    }
    Ok(result)
}

/// Decrypts an array of bytes using the AES-128 cipher
/// 
/// # Arguments
/// 
/// * `input` - The array of bytes to decrypt
/// * `key` - The key to use for decryption
/// 
/// # Example
/// 
/// ```
/// use cryptographic_primitives::{aes_128_encrypt, aes_128_decrypt};
/// 
/// let plaintext = b"Hello, world!";
/// let ciphertext = aes_128_encrypt(plaintext, 15).unwrap();
/// let decrypted = aes_128_decrypt(&ciphertext, 15).unwrap();
/// 
/// assert_eq!(decrypted, plaintext.to_vec());
/// 
/// ```
/// 
/// # Errors
/// 
/// * `Input must not be empty` - If the input array is empty
pub fn aes_128_decrypt(input: &[u8], key: u128) -> Result<Vec<u8>, &'static str> {

    if input.is_empty() {
        return Err("Input must not be empty");
    }

    let input_size = input.len();
    let mut subkeys = kdf(&key.to_le_bytes(), 6).unwrap();
    let mut result = input.to_vec();
    let mut s_box = [0u8; 256];
    initialize_aes_sbox(&mut s_box);

    // split each subkey in half to generate 128-bit subkeys
    for i in 0..subkeys.len() {
        let mut subkey1 = subkeys[i].to_vec();
        let subkey2 = subkey1.split_off(16);
        subkeys[i] = subkey1;
        subkeys.push(subkey2);
    }
    subkeys.truncate(11);

    for i in (0..10).rev() {

        // go over each 128-bit block of input
        for j in (0..input_size).step_by(16) {

            // First XOR step
            if i == 9 {
                for l in 0..16 {
                    result[j + l] ^= subkeys[10][l];
                }
            }
            
            let temp_result = result[j..j + 16].to_vec();

            // Inverse shift-rows step
            for l in 0..16 {    
                result[j + l] = temp_result[(j + l + (4 - l % 4) * 4) % 16];
            }

            // Inverse sub-bytes step
            for l in 0..16 {
                result[j + l] = s_box.iter().position(|&x| x == result[j + l]).unwrap() as u8;
            }

            // Add round key
            for l in 0..16 {
                result[j + l] ^= subkeys[i as usize][l];
            }

            // Inverse mix-columns step
            if i > 0 { // skip this step in the first round
                for l in (0..16).step_by(4) {
                    let mut column = [0u8; 4];
                    for k in 0..4 {
                        column[k] = result[j + l + k];
                    }
                    gmix_column_inv(&mut column);
                    for k in 0..4 {
                        result[j + l + k] = column[k];
                    }
                }
            }
        }
    }

    // remove all trailing null bytes
    while result.last() == Some(&0) {
        result.pop();
    }

    Ok(result)
}
