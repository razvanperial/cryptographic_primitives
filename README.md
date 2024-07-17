Rust Cryptographic Primitives
=============================
[<img alt="github" src="https://img.shields.io/badge/github-razvanperial/cryptographic_primitives-8da0cb?style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/razvanperial/cryptographic_primitives)
[<img alt="crates.io" src="https://img.shields.io/crates/v/cryptographic_primitives.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/cryptographic_primitives)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-cryptographic_primitives-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="20">](https://docs.rs/cryptographic_primitives/0.1.0/cryptographic_primitives/)

This repository contains a collection of cryptographic primitives implemented in Rust. The goal is to provide a comprehensive set of cryptographic primitives that are easy to use and hard to misuse. 

This crate was done as a personal project to learn Rust and cryptography, implementing some of the algorithms I learned in the "Secure and Dependable Systems" course at my university. The code is open source and I am happy to receive contributions and feedback. Feel free to open an issue or a pull request on [this repository](https://github.com/razvanperial/cryptographic_primitives).

If this crate is useful to you, please consider giving it a star on [GitHub](https://github.com/razvanperial/cryptographic_primitives) :)

## Features

The crate currently provides the following cryptographic primitives, with an encryption and decryption function for each:

- Rail Fence Cipher
- Route Cipher
- Feistel Network
- Substitution-Permutation Network (SPN)
- Advanced Encryption Standard (AES)

The following cryptographic primitives are planned to be implemented in the future:

- Electronic Codebook (ECB) mode
- Cipher Block Chaining (CBC) mode
- Counter (CTR) mode
- Output Feedback (OFB) mode
- Rivest-Shamir-Adleman (RSA) algorithm

The `helpers` module provides the following helper functions for cryptographic algorithms:

- `rotl8`
- `initialize_aes_sbox`
- `permute`
- `feistel_round_function`
- `kdf`
- `gmix_column`
- `gmix_column_inv`

The `constants` module provides some useful constants for cryptographic algorithms, such as:
- and example `S-Box`
- an example `P-Box`
- `MIX_COLUMNS_LOOKUP_2`, `MIX_COLUMNS_LOOKUP_3`, `MIX_COLUMNS_LOOKUP_9`, `MIX_COLUMNS_LOOKUP_11`, `MIX_COLUMNS_LOOKUP_13`, `MIX_COLUMNS_LOOKUP_14` lookup tables for the AES MixColumns operation


For any suggestions or requests, feel free to open an issue on [this repository](https://github.com/razvanperial/cryptographic_primitives).

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
cryptographic_primitives = "0.1.0"
```
You can also use `cargo` to add the dependency to your `Cargo.toml`:

```sh
cargo add cryptographic_primitives
```

Then, simply import the crate and use the cryptographic primitives:

```rust
use cryptographic_primitives::*;
```

## Example

Here is an example of using the `sub_per_box_encrypt` and `sub_per_box_decrypt` functions to encrypt and decrypt a message using the substitution-permutation network (SPN) algorithm.

```rust
use cryptographic_primitives::{sub_per_box_encrypt, sub_per_box_decrypt};

let plaintext = b"Hello, world!";
// key = 15, rounds = 3
let ciphertext = sub_per_box_encrypt(plaintext, 15, 3).unwrap();
let decrypted = sub_per_box_decrypt(&ciphertext, 15, 3).unwrap();

assert_eq!(plaintext.to_vec(), decrypted);
```

## License

This project is licensed under the [MIT license](https://github.com/razvanperial/cryptographic_primitives/blob/master/LICENSE).
