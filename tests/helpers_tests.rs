#[cfg(test)]
mod tests {
    use cryptographic_primitives::{constants::P_BOX, helpers::{
        feistel_round_function, gmix_column, gmix_column_inv, initialize_aes_sbox, kdf, permute, rotl8, xor_bytes
    }};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    #[test]
    fn test_rotl8() {
        let result = rotl8(0b10110010, 3).unwrap();
        assert_eq!(result, 0b10010101);

        let result = rotl8(0b10110010, 0);
        assert_eq!(result, Ok(0b10110010));

        let result = rotl8(0b10110010, 8);
        assert_eq!(result, Err("Shift value must be between 0 and 7"));

        let result = rotl8(0b10110010, 7).unwrap();
        assert_eq!(result, 0b01011001);
    }

    #[test]
    fn test_initialize_aes_sbox() {
        let mut sbox = [0u8; 256];
        initialize_aes_sbox(&mut sbox).unwrap();

        assert_eq!(sbox[0x00], 0x63);
        assert_eq!(sbox[0x7C], 0x10);
        assert_eq!(sbox[0x52], 0x00);
        assert_eq!(sbox[0xFF], 0x16);

        let unique_values: std::collections::HashSet<u8> = sbox.iter().cloned().collect();
        assert_eq!(unique_values.len(), 256);
    }

    #[test]
    fn test_permute() {
        let input = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let permuted = permute(&input, false, &P_BOX).unwrap();

        assert_ne!(permuted, input);

        let reversed = permute(&permuted, true, &P_BOX).unwrap();

        assert_eq!(reversed, input);
    
        let input = vec![];
        let permuted = permute(&input, false, &P_BOX);

        assert!(permuted.is_err());
    }

    #[test]
    fn test_feistel_round_function() {
        let input = b"data";
        let subkey = b"key";
        let result = feistel_round_function(input, subkey).unwrap();
        assert_eq!(result.len(), 32);

        let input = b"";
        let subkey = b"key";
        let result = feistel_round_function(input, subkey).unwrap();
        assert_eq!(result.len(), 32);

        let input = b"data";
        let subkey1 = b"key1";
        let subkey2 = b"key2";
        let result1 = feistel_round_function(input, subkey1).unwrap();
        let result2 = feistel_round_function(input, subkey2).unwrap();

        assert_ne!(result1, result2); 
    }

    #[test]
    fn test_kdf() {
        // Check that the correct number of subkeys are generated
        let initial_key = b"initial_key";
        let subkeys = kdf(initial_key, 3).unwrap();
        assert_eq!(subkeys.len(), 3);

        // Check that more rounds produce more subkeys
        let initial_key = b"initial_key";
        let subkeys_1 = kdf(initial_key, 3).unwrap();
        let subkeys_2 = kdf(initial_key, 5).unwrap();
        assert_eq!(subkeys_1.len(), 3);
        assert_eq!(subkeys_2.len(), 5);


        // Check that valid subkeys are still generated even if the initial key is empty
        let initial_key = b"";
        let subkeys = kdf(initial_key, 3).unwrap();
        assert_eq!(subkeys.len(), 3);
        assert_eq!(subkeys[0].len(), 32); // Length of HMAC-SHA256 output

        let invalid_key = b""; // This is less than 32 bytes
    
        let result = Hmac::<Sha256>::new_from_slice(invalid_key);

        println!("{:?}", result.unwrap());
        

    }

    #[test]
    fn test_gmix_column() {
        let mut column = [0x87, 0x6E, 0x46, 0xA6];
        gmix_column(&mut column);
        assert_eq!(column, [0x47, 0x37, 0x94, 0xED]);

        let mut column = [0x00, 0x00, 0x00, 0x00];
        gmix_column(&mut column);
        assert_eq!(column, [0x00, 0x00, 0x00, 0x00]);

        let mut column = [0xFF, 0xFF, 0xFF, 0xFF];
        gmix_column(&mut column);
        assert_eq!(column, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_gmix_column_inv() {
        let mut column = [0x47, 0x6E, 0x27, 0xD5];
        gmix_column_inv(&mut column);
        assert_eq!(column, [0xD7, 0x7F, 0x1A, 0x69]);

        let mut column = [0x00, 0x00, 0x00, 0x00];
        gmix_column_inv(&mut column);
        assert_eq!(column, [0x00, 0x00, 0x00, 0x00]);

        let mut column = [0x8D, 0x8D, 0x8D, 0x8D];
        gmix_column_inv(&mut column);
        assert_eq!(column, [0x8D, 0x8D, 0x8D, 0x8D]);
    }

    #[test]
    fn test_xor_bytes() {
        let input = [0xFF, 0xAA, 0x55, 0x00];
        let key = [0x00, 0xFF, 0xAA, 0x55];
        let expected_output = [0xFF, 0x55, 0xFF, 0x55]; // XOR of each pair of bytes
        let result = xor_bytes(&input, &key).unwrap();
        assert_eq!(result, expected_output);

        let input = [0xAA, 0xAA, 0xAA, 0xAA];
        let key = [0xAA, 0xAA, 0xAA, 0xAA];
        let expected_output = [0x00, 0x00, 0x00, 0x00]; // XOR of identical values is 0
        let result = xor_bytes(&input, &key).unwrap();
        assert_eq!(result, expected_output);

        let input = [0x01, 0x02, 0x03, 0x04];
        let key = [0x00, 0x00, 0x00, 0x00];
        let expected_output = [0x01, 0x02, 0x03, 0x04]; // XOR with zero leaves the input unchanged
        let result = xor_bytes(&input, &key).unwrap();
        assert_eq!(result, expected_output);

        let input: [u8; 0] = [];
        let key: [u8; 0] = [];
        let result = xor_bytes(&input, &key).unwrap();
        assert_eq!(result.len(), 0); 

        let input = [0x01, 0x02, 0x03];
        let key = [0x00, 0x00]; // Mismatched length
        let result = xor_bytes(&input, &key);
        assert!(result.is_err()); 

        let input = [0xFF, 0xFF, 0xFF, 0xFF];
        let key = [0xFF, 0xFF, 0xFF, 0xFF];
        let expected_output = [0x00, 0x00, 0x00, 0x00]; // XOR of all ones results in zero
        let result = xor_bytes(&input, &key).unwrap();
        assert_eq!(result, expected_output);

        let input: Vec<u8> = vec![0xAB; 1024]; // 1024 bytes of 0xAB
        let key: Vec<u8> = vec![0xCD; 1024]; // 1024 bytes of 0xCD
        let result = xor_bytes(&input, &key).unwrap();
        for &byte in result.iter() {
            assert_eq!(byte, 0x66); // 0xAB ^ 0xCD == 0x66
        }
    }

}