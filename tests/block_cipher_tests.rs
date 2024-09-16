#[cfg(test)]
mod tests {
    use cryptographic_primitives::{
        feistel_network_encrypt, feistel_network_decrypt,
        sub_per_box_encrypt, sub_per_box_decrypt,
        aes_128_encrypt, aes_128_decrypt,
    };
    
    use cryptographic_primitives::block_ciphers::{
        ecb_encrypt, ecb_decrypt,
        cbc_encrypt, cbc_decrypt,
        ofb_encrypt, ofb_decrypt,
        ctr_encrypt, ctr_decrypt
    };

    const PLAINTEXT1: &[u8; 13] = b"Hello, world!";
    const PLAINTEXT2: &[u8; 1] = b"A";
    const PLAINTEXT3: &[u8; 29] = b"!@#$%^&*()_+-={}[]|:;\"'<>,.?/";
    const PLAINTEXT4: &[u8; 15] = b"AAAAAAAAAAAAAAA";
    const PLAINTEXT5: &[u8; 164] = b"This is a very long string that we will use to test the encryption function. It should handle long inputs gracefully and return the correct result after decryption.";
    const PLAINTEXT6: &[u8; 16] = b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
    const PLAINTEXT7: &[u8; 16] = b"ThisIs 16 Bytes!";
    const PLAINTEXT8: &[u8; 15] = b"ThisIs 15 bytes";

    const KEY1: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
    const KEY2: u128 = 0x1;
    const KEY3: u128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    const KEY4: u128 = 0x00000000000000000000000000000000;
    const KEY5: u128 = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;
    const KEY6: u128 = 0x55555555555555555555555555555555;
    const KEY7: u128 = 0x0123456789ABCDEF0123456789ABCDEF;
    const KEY8: u128 = 0xFEDCBA9876543210FEDCBA9876543210;
    const KEY9: u128 = 0x0000000000000000FFFFFFFFFFFFFFFF;

    const IV1: [u8; 16] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    const IV2: [u8; 16] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const IV3: [u8; 16] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    const IV4: [u8; 16] = [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
    const IV5: [u8; 16] = [0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];
    const IV6: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    const IV7: [u8; 16] = [0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00];
    const IV8: [u8; 16] = [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01];
    const IV9: [u8; 16] = [0x3C, 0xE8, 0x29, 0x75, 0x1A, 0x2B, 0x6C, 0x8D, 0x5F, 0x92, 0x7E, 0x3B, 0x4A, 0x6D, 0x9C, 0xF1];

    const NONCE1: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    const NONCE2: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const NONCE3: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    const NONCE4: [u8; 8] = [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
    const NONCE5: [u8; 8] = [0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];
    const NONCE6: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const NONCE7: [u8; 8] = [0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08];
    const NONCE8: [u8; 8] = [0x8F, 0x3B, 0x6E, 0xDA, 0x4C, 0x72, 0x9F, 0xA1];


    const PLAINTEXTS: [&[u8]; 8] = [
        PLAINTEXT1, PLAINTEXT2, PLAINTEXT3, PLAINTEXT4,
        PLAINTEXT5, PLAINTEXT6, PLAINTEXT7, PLAINTEXT8
    ];

    const KEYS: [u128; 9] = [
        KEY1, KEY2, KEY3, KEY4, KEY5, KEY6, KEY7, KEY8, KEY9
    ];

    const IVS: [[u8; 16]; 9] = [
        IV1, IV2, IV3, IV4, IV5, IV6, IV7, IV8, IV9
    ];

    const NONCES: [[u8; 8]; 8] = [
        NONCE1, NONCE2, NONCE3, NONCE4, NONCE5, NONCE6, NONCE7, NONCE8
    ];

    #[test]
    fn ecb_aes_128_test() {
        for key in KEYS.iter() {
            for plaintext in PLAINTEXTS.iter() {
                let ciphertext = ecb_encrypt(*&plaintext, *key, aes_128_encrypt).unwrap();
                let decrypted = ecb_decrypt(&ciphertext, *key, aes_128_decrypt).unwrap();
                assert_eq!(*plaintext, decrypted);
            }
        }
    }

    #[test]
    fn cbc_aes_128_test() {
        for key in KEYS.iter() {
            for plaintext in PLAINTEXTS.iter() {
                for iv in IVS.iter() {
                    let ciphertext = cbc_encrypt(*&plaintext, *key, *iv, aes_128_encrypt).unwrap();
                    let decrypted = cbc_decrypt(&ciphertext, *key, *iv, aes_128_decrypt).unwrap();
                    assert_eq!(*plaintext, decrypted);
                }
            }
        }
    }

    #[test]
    fn ofb_aes_128_test() {
        for key in KEYS.iter() {
            for plaintext in PLAINTEXTS.iter() {
                for iv in IVS.iter() {
                    let ciphertext = ofb_encrypt(*&plaintext, *key, *iv, aes_128_encrypt).unwrap();
                    let decrypted = ofb_decrypt(&ciphertext, *key, *iv, aes_128_encrypt).unwrap();
                    assert_eq!(*plaintext, decrypted);
                }
            }
        }
    }

    #[test]
    fn ctr_aes_128_test() {
        for key in KEYS.iter() {
            for plaintext in PLAINTEXTS.iter() {
                for nonce in NONCES.iter() {
                    let ciphertext = ctr_encrypt(*&plaintext, *key, *nonce, aes_128_encrypt).unwrap();
                    let decrypted = ctr_decrypt(&ciphertext, *key, *nonce, aes_128_encrypt).unwrap();
                    assert_eq!(*plaintext, decrypted);
                }
            }
        }
    }

    #[test]
    fn ecb_sub_per_box_test() {
        let sub_per_box_encrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
            sub_per_box_encrypt(input, key, 16)
        };
        let sub_per_box_decrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
            sub_per_box_decrypt(input, key, 16)
        };
        for key in KEYS.iter() {
            for plaintext in PLAINTEXTS.iter() {
                let ciphertext = ecb_encrypt(*&plaintext, *key, sub_per_box_encrypt_fn).unwrap();
                let decrypted = ecb_decrypt(&ciphertext, *key, sub_per_box_decrypt_fn).unwrap();
                assert_eq!(*plaintext, decrypted);
            }
        }
    }

    #[test]
    fn cbc_sub_per_box_test() {
        let sub_per_box_encrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
            sub_per_box_encrypt(input, key, 16)
        };
        let sub_per_box_decrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
            sub_per_box_decrypt(input, key, 16)
        };
        for key in KEYS.iter() {
            for plaintext in PLAINTEXTS.iter() {
                for iv in IVS.iter() {
                    let ciphertext = cbc_encrypt(*&plaintext, *key, *iv, sub_per_box_encrypt_fn).unwrap();
                    let decrypted = cbc_decrypt(&ciphertext, *key, *iv, sub_per_box_decrypt_fn).unwrap();
                    assert_eq!(*plaintext, decrypted);
                }
            }
        }
    }

    #[test]
    fn ofb_sub_per_box_test() {
        let sub_per_box_encrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
            sub_per_box_encrypt(input, key, 16)
        };
        for key in KEYS.iter() {
            for plaintext in PLAINTEXTS.iter() {
                for iv in IVS.iter() {
                    let ciphertext = ofb_encrypt(*&plaintext, *key, *iv, sub_per_box_encrypt_fn).unwrap();
                    let decrypted = ofb_decrypt(&ciphertext, *key, *iv, sub_per_box_encrypt_fn).unwrap();
                    assert_eq!(*plaintext, decrypted);
                }
            }
        }
    }

    #[test]
    fn ctr_sub_per_box_test() {
        let sub_per_box_encrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
            sub_per_box_encrypt(input, key, 16)
        };
        for key in KEYS.iter() {
            for plaintext in PLAINTEXTS.iter() {
                for nonce in NONCES.iter() {
                    let ciphertext = ctr_encrypt(*&plaintext, *key, *nonce, sub_per_box_encrypt_fn).unwrap();
                    let decrypted = ctr_decrypt(&ciphertext, *key, *nonce, sub_per_box_encrypt_fn).unwrap();
                    assert_eq!(*plaintext, decrypted);
                }
            }
        }
    }

    #[test]
    fn ecb_feistel_network_test() {
        let feistel_network_encrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
            feistel_network_encrypt(input, key, 16)
        };
        let feistel_network_decrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
            feistel_network_decrypt(input, key, 16)
        };
        for key in KEYS.iter() {
            for plaintext in PLAINTEXTS.iter() {
                let ciphertext = ecb_encrypt(*&plaintext, *key, feistel_network_encrypt_fn).unwrap();
                let decrypted = ecb_decrypt(&ciphertext, *key, feistel_network_decrypt_fn).unwrap();
                assert_eq!(*plaintext, decrypted);
            }
        }
    }

    #[test]
    fn cbc_feistel_network_test() {
        let feistel_network_encrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
            feistel_network_encrypt(input, key, 16)
        };
        let feistel_network_decrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
            feistel_network_decrypt(input, key, 16)
        };
        for key in KEYS.iter() {
            for plaintext in PLAINTEXTS.iter() {
                for iv in IVS.iter() {
                    let ciphertext = cbc_encrypt(*&plaintext, *key, *iv, feistel_network_encrypt_fn).unwrap();
                    let decrypted = cbc_decrypt(&ciphertext, *key, *iv, feistel_network_decrypt_fn).unwrap();
                    assert_eq!(*plaintext, decrypted);
                }
            }
        }
    }

    #[test]
    fn ofb_feistel_network_test() {
        let feistel_network_encrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
            feistel_network_encrypt(input, key, 16)
        };
        for key in KEYS.iter() {
            for plaintext in PLAINTEXTS.iter() {
                for iv in IVS.iter() {
                    let ciphertext = ofb_encrypt(*&plaintext, *key, *iv, feistel_network_encrypt_fn).unwrap();
                    let decrypted = ofb_decrypt(&ciphertext, *key, *iv, feistel_network_encrypt_fn).unwrap();
                    assert_eq!(*plaintext, decrypted);
                }
            }
        }
    }

    #[test]
    fn ctr_feistel_network_test() {
        let feistel_network_encrypt_fn = |input: &[u8], key: u128| -> Result<Vec<u8>, &'static str> {
            feistel_network_encrypt(input, key, 16)
        };
        for key in KEYS.iter() {
            for plaintext in PLAINTEXTS.iter() {
                for nonce in NONCES.iter() {
                    let ciphertext = ctr_encrypt(*&plaintext, *key, *nonce, feistel_network_encrypt_fn).unwrap();
                    let decrypted = ctr_decrypt(&ciphertext, *key, *nonce, feistel_network_encrypt_fn).unwrap();
                    assert_eq!(*plaintext, decrypted);
                }
            }
        }
    }
}


