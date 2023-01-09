extern crate crypto;

use std::env;
use std::fs::File;
// use std::io::Read;
use std::process;
use std::process::Command;

use rustc_serialize::hex::FromHex;
use std::iter::repeat;
use crypto::sha2::Sha512;

use aes::Aes128;
type Aes128Ige = Ige<Aes128, Pkcs7>;

use block_modes::{BlockMode, Ige};
use block_modes::block_padding::Pkcs7;
// use hex_literal;
use std::str;



pub fn run() {
    let args: Vec<String> = env::args().collect();

    let command = get_command_from_args(&args).unwrap_or_else(| err | {
        eprintln!("Problem getting the command from arguments: {}", err);
        process::exit(1);
    });

    if command == "add" {
        println!("You want to add an entry");
        create_temp_entry();
    }
    else if command == "del" {
        println!("You want to delete an entry");
    }
    else if command == "list" {
        println!("You want to list entries");
    }
    else if command == "read" {
        println!("You want to read an entry");
    }
    else {
        println!("Invalid Command!");
    }
}

pub fn get_command_from_args(args: &[String]) -> Result<String, &str> {
    if args.len() < 2 {
        return Err("No command was given!");
    }

    Ok(args[1].clone())

}

pub fn create_temp_entry() {
    let editor = env::var("EDITOR").unwrap_or_else(| err | {
        eprintln!("EDITOR environment variable not set: {}", err);
        process::exit(1);
    });

    let mut file_path = env::current_dir().unwrap_or_else(| err | {
        eprintln!("Could not define temporary location for new entry: {}", err);
        process::exit(1);
    });
    file_path.push("tmp/temp_entry.txt");
    if let Err(e) = File::create(&file_path) {
        eprintln!("Could not create file: {}", e);
        process::exit(1);
    }

    if let Err(e) = Command::new(editor).arg(&file_path).status() {
        eprintln!("Editor error: {}", e);
        process::exit(1);
    }

}

fn hex_to_bytes(s: String) -> Vec<u8> {
    s.as_str().from_hex().unwrap()
}

pub fn hash_password(password: &str) -> Vec<u8> {
    let salt = String::from("000102030405060708090a0b0c");
    let info = String::from("f0f1f2f3f4f5f6f7f8f9");
    let len= 64;

    let dig=Sha512::new();

    let salt=&hex_to_bytes( salt.clone())[..];
    let info=&hex_to_bytes( info.clone())[..];

    let ikm = String::from(password).into_bytes();

    let mut prk: Vec<u8> = repeat(0).take(len).collect();

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
        let expected = hex_to_bytes(String::from("607d4eca8c017d444c74b3256eb6dcffcfe1fced2be4ebe6e0e1915fd469f2425c9c1354787c9a35964a8b3990b7ccb1e50d5e26e3e33dca295e759368abc4df"));
        assert_eq!(expected, hash_password("hello"));
    }

    #[test]
    fn encrypt_text() {
        let key = hex::decode(String::from("000102030405060708090A0B0C0D0E0F")).expect("failed to decode the key!");
        let iv = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let message = String::from("Hello world!");

        assert_eq!(encrypt_entry(&key, &iv, message), String::from("eb8bbeb3c5d158d84dd2173ec825d157"));
    }

    #[test]
    fn decrypt_text() {
        let key = hex::decode(String::from("000102030405060708090A0B0C0D0E0F")).expect("failed to decode the key!");
        let iv = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let ciphertext = String::from("eb8bbeb3c5d158d84dd2173ec825d157");

        assert_eq!(decrypt_entry(&key, &iv, ciphertext), String::from("Hello world!"));
    }
}