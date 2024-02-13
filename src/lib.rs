//! # cryptograhpic_primitives
//! 'cryptograhpic_primitives' is a crate that provides implementations of various cryptographic primitives.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use bitvec::prelude::*;

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

fn kdf(initial_key: &[u8], num_rounds: usize) -> Result<Vec<Vec<u8>>, &'static str> { 
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

fn feistel_round_function(input: &[u8], subkey: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut mac = match Hmac::<Sha256>::new_from_slice(subkey) {
        Ok(m) => m,
        Err(_) => panic!("HMAC creation failed"),
    };

    mac.update(input);

    Ok(mac.finalize().into_bytes().to_vec())
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

const S_BOX:[u8; 256] = [
    99, 152, 15, 157, 33, 158, 53, 11, 182, 195, 21, 14, 120, 17, 89, 203, 59,
    244, 1, 147, 175, 32, 214, 52, 133, 54, 148, 146, 225, 51, 111, 124, 16, 
    223, 79, 235, 60, 145, 231, 230, 136, 164, 43, 142, 206, 188, 243, 88, 255, 
    44, 247, 216, 38, 185, 123, 126, 233, 198, 202, 77, 179, 208, 180, 209, 150,
    125, 140, 240, 224, 55, 2, 13, 204, 159, 254, 128, 160, 196, 189, 226, 121, 
    166, 27, 103, 229, 28, 122, 82, 80, 73, 36, 41, 105, 24, 222,  9, 168, 34, 
    65, 63, 74, 241, 66, 227, 69, 40, 57, 127, 45, 132, 50, 48, 138, 61, 135,
    242, 171, 71, 18, 90, 153, 170, 4, 112, 0, 177, 141, 207, 10, 35, 118, 155, 
    232, 29, 169, 178, 129, 154, 192, 70, 234, 37, 104, 67, 249, 237, 100, 215,
    47, 115,  5, 42, 113, 96, 248, 144, 97, 200, 162, 64, 19, 109, 49, 85, 106, 
    149, 186, 238, 98, 250, 20, 163, 236, 76, 86, 114, 78, 94, 102, 183, 83, 92,
    91, 173, 190, 217, 181, 81, 165, 252,  7, 137, 39, 107, 46, 95, 58, 194, 
    174, 119, 172, 31, 134, 253, 156, 205, 211, 197, 199, 130, 68, 93, 213, 116, 
    218, 245,  3, 108, 221, 72, 62, 228, 143, 12, 117, 219, 131, 75, 151, 246,
    184, 193, 167, 84, 30, 22, 187, 210, 239, 212, 26, 220, 101, 176, 25, 56, 
    191, 161,  6, 87, 23, 201, 139,  8, 251, 110
];

const P_BOX:[u8; 128] = [
    17, 19, 28, 97, 83, 61, 69, 85, 65, 30, 36, 126, 107, 121, 94, 41, 117,
    75, 52, 110, 84, 100, 103, 58, 22, 125, 82, 43, 119, 53, 122, 90, 35, 73,
    74, 95, 37, 32, 55, 111, 7, 66, 23, 68, 31, 50, 62, 15, 108, 99, 120,
    54, 102, 70, 13, 81, 60, 3, 34, 51, 48, 79, 92, 40, 12, 44, 29, 11,
    67, 38, 124, 98, 2, 18, 47, 88, 89, 71, 4, 118, 127, 123, 86, 59, 9,
    77, 25, 39, 113, 27, 1, 114, 49, 20, 14, 64, 109, 5, 80, 112, 46, 72,
    6, 63, 104, 93, 56, 0, 106, 42, 87, 101, 91, 115, 26, 45, 33, 24, 105,
    21, 78, 96, 76, 16, 10, 57, 8, 116
];

// permute a block of 128 bits using the P_BOX defined above
fn permute(input: &[u8], reverse: bool) -> Result<Vec<u8>, &'static str> {
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