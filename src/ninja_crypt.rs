extern crate crypto;

use std::iter::repeat;
use crypto::sha3::Sha3;

use aes::Aes128;
type Aes128Ige = Ige<Aes128, Pkcs7>;

use block_modes::{BlockMode, Ige};
use block_modes::block_padding::Pkcs7;
// use hex_literal;
use std::str;

use crate::ninja_utils;



pub fn hash(text: &str, len: usize) -> Vec<u8> {
    let salt = String::from("000102030405060708090a0b0c");
    let info = String::from("f0f1f2f3f4f5f6f7f8f9");

    let salt=&ninja_utils::hex_to_bytes( salt.clone())[..];
    let info=&ninja_utils::hex_to_bytes( info.clone())[..];
    
    let dig=Sha3::sha3_512();

    let ikm = String::from(text).into_bytes();

    let mut prk: Vec<u8> = repeat(0).take(64).collect();

    crypto::hkdf::hkdf_extract(dig, &salt[..], &ikm[..], &mut prk);

    let mut okm: Vec<u8> = repeat(0).take(len as usize).collect();

    crypto::hkdf::hkdf_expand(dig, &prk[..], &info[..], &mut okm);
    
    return okm;
}

pub fn encrypt_entry(key: &[u8], iv: &[u8], text: String) -> String {
    let cipher = Aes128Ige::new_from_slices(&key, &iv).unwrap();
    let plaintext=text.as_bytes();
    let pos = plaintext.len();

    let mut buffer = [0u8; 128];
    buffer[..pos].copy_from_slice(plaintext);
    let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();

    hex::encode(ciphertext)
}

pub fn decrypt_entry(key: &[u8], iv: &[u8], ciphertext: String) -> String {
    let cipher = Aes128Ige::new_from_slices(&key, &iv).unwrap();
    let mut buffer = hex::decode(ciphertext).unwrap().to_vec();
    let decrypted_ciphertext = cipher.decrypt(&mut buffer).unwrap();

    String::from(str::from_utf8(decrypted_ciphertext).unwrap())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_password_hash() {
        let expected = ninja_utils::hex_to_bytes(String::from("607d4eca8c017d444c74b3256eb6dcffcfe1fced2be4ebe6e0e1915fd469f2425c9c1354787c9a35964a8b3990b7ccb1e50d5e26e3e33dca295e759368abc4df"));
        assert_eq!(expected, hash("hello", 64));
    }

    #[test]
    fn encrypt_text() {
        let key = hex::decode(String::from("000102030405060708090A0B0C0D0E0F")).expect("failed to decode the key!");
        // let key = hex::decode(String::from("123456")).expect("failed to decode the key!");
        let iv = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let message = String::from("Hello world!");

        assert_eq!(encrypt_entry(&key, &iv, message), String::from("eb8bbeb3c5d158d84dd2173ec825d157"));
    }

    #[test]
    fn decrypt_text() {
        let key = hex::decode(String::from("000102030405060708090A0B0C0D0E0F")).expect("failed to decode the key!");
        // let key = hex::decode(String::from("123456")).expect("failed to decode the key!");
        let iv = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let ciphertext = String::from("eb8bbeb3c5d158d84dd2173ec825d157");

        assert_eq!(decrypt_entry(&key, &iv, ciphertext), String::from("Hello world!"));
    }
}