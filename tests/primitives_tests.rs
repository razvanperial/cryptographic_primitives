#[cfg(test)]

mod tests {
    use cryptographic_primitives::{
        rail_fence_cipher_encrypt, rail_fence_cipher_decrypt,
        route_cipher_encrypt, route_cipher_decrypt,
        feistel_network_encrypt, feistel_network_decrypt,
        sub_per_box_encrypt, sub_per_box_decrypt,
        aes_128_encrypt, aes_128_decrypt
    };

    const PLAINTEXT1: &[u8; 13] = b"Hello, world!";
    const PLAINTEXT2: &[u8; 1] = b"A";
    const PLAINTEXT3: &[u8; 29] = b"!@#$%^&*()_+-={}[]|:;\"'<>,.?/";
    const PLAINTEXT4: &[u8; 15] = b"AAAAAAAAAAAAAAA";
    const PLAINTEXT5: &[u8; 164] = b"This is a very long string that we will use to test the encryption function. It should handle long inputs gracefully and return the correct result after decryption.";
    const PLAINTEXT6: &[u8; 16] = b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
    const PLAINTEXT7: &[u8; 16] = b"ThisIs 16 Bytes!";

    const KEY1: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
    const KEY2: u128 = 0x1;
    const KEY3: u128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    const KEY4: u128 = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;
    const KEY5: u128 = 0x55555555555555555555555555555555;
    const KEY6: u128 = 0x0123456789ABCDEF0123456789ABCDEF;
    const KEY7: u128 = 0xFEDCBA9876543210FEDCBA9876543210;
    const KEY8: u128 = 0x0000000000000000FFFFFFFFFFFFFFFF;

    const ROUND1: u32 = 1;
    const ROUND2: u32 = 5;
    const ROUND3: u32 = 50;

    const PLAINTEXTS: [&[u8]; 7] = [
        PLAINTEXT1, PLAINTEXT2, PLAINTEXT3, PLAINTEXT4,
        PLAINTEXT5, PLAINTEXT6, PLAINTEXT7
    ];

    const KEYS: [u128; 8] = [
        KEY1, KEY2, KEY3, KEY4, KEY5, KEY6, KEY7, KEY8
    ];

    const ROUNDS: [u32; 3] = [
        ROUND1, ROUND2, ROUND3
    ];

    #[test]
    fn test_rail_fence_cipher() {
        for plaintext in PLAINTEXTS.iter() {
            for key in KEYS.iter() {
                let ciphertext = rail_fence_cipher_encrypt(&plaintext, *key).unwrap();
                let decrypted = rail_fence_cipher_decrypt(&ciphertext, *key).unwrap();

                assert_eq!(&decrypted[..], *plaintext);
            }
        }

        // Error case: Empty input
        let result = rail_fence_cipher_encrypt(b"", 3);
        assert!(result.is_err());

        // Error case: Key smaller than 1
        let result = rail_fence_cipher_encrypt(b"Hello, world!", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_route_cipher() {
        for plaintext in PLAINTEXTS.iter() {
            for key in KEYS.iter() {
                let ciphertext = route_cipher_encrypt(&plaintext, *key).unwrap();
                let decrypted = route_cipher_decrypt(&ciphertext, *key).unwrap();

                assert_eq!(decrypted, *plaintext);
            }
        }

        // Error case: Empty input
        let result = route_cipher_encrypt(b"", 3);
        assert!(result.is_err());

        // Error case: Key smaller than 1
        let result = route_cipher_encrypt(b"Hello, world!", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_feistel_network_cipher() {
        for plaintext in PLAINTEXTS.iter() {
            for key in KEYS.iter() {
                for rounds in ROUNDS.iter() {
                    let ciphertext = feistel_network_encrypt(plaintext, *key, *rounds).unwrap();
                    let decrypted = feistel_network_decrypt(&ciphertext, *key, *rounds).unwrap();

                    assert_eq!(&decrypted[..], *plaintext);
                }
            }
        }

        // Error case: Empty input
        let result = feistel_network_encrypt(&[], KEY1, ROUND1);
        assert!(result.is_err());

        // Error case: Less than 1 round
        let result = feistel_network_encrypt(PLAINTEXT1, KEY1, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_sub_per_box_cipher() {
        for plaintext in PLAINTEXTS.iter() {
            for key in KEYS.iter() {
                for rounds in ROUNDS.iter() {
                    let ciphertext = sub_per_box_encrypt(plaintext, *key, *rounds).unwrap();
                    let decrypted = sub_per_box_decrypt(&ciphertext, *key, *rounds).unwrap();

                    assert_eq!(&decrypted[..], *plaintext);
                }
            }
        }

        // Error case: Empty input
        let result = sub_per_box_encrypt(&[], KEY1, ROUND1);
        assert!(result.is_err());

        // Error case: Less than 1 round
        let result = sub_per_box_decrypt(PLAINTEXT1, KEY1, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_128_cipher() {
        for plaintext in PLAINTEXTS.iter() {
            for key in KEYS.iter() {
                let ciphertext = aes_128_encrypt(plaintext, *key).unwrap();
                let decrypted = aes_128_decrypt(&ciphertext, *key).unwrap();

                assert_eq!(&decrypted[..], *plaintext);
            }
        }

        // Error case: Empty input
        let result = aes_128_encrypt(&[], KEY1);
        assert!(result.is_err());     
    }
}