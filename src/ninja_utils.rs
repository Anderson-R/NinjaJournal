use std::fs::{File, read_to_string};
use std::io::Result;
use std::io::{prelude::*, BufReader, stdin,stdout,Write};
use rustc_serialize::hex::FromHex;
use std::env;
use std::process;

use crate::ninja_crypt;

extern crate rpassword;
use rpassword::read_password;



pub fn ask_user_input(ask: &str) -> String {
    let mut input=String::new();
    print!("{}", ask);
    stdout().flush().unwrap();
    stdin().read_line(&mut input).expect("Did not enter a correct string");
    if let Some('\n')=input.chars().next_back() {
        input.pop();
    }
    if let Some('\r')=input.chars().next_back() {
        input.pop();
    }
    return input;
}

pub fn ask_user_secret_input(ask: &str) -> String {
    print!("{}", ask);
    stdout().flush().unwrap();
    read_password().unwrap()
}

pub fn get_rand_bytes(buffer: &mut [u8]) -> Result<()> {
    let mut file = File::open("/dev/urandom")?;
    file.read_exact(buffer)
}

pub fn hex_to_bytes(s: String) -> Vec<u8> {
    s.as_str().from_hex().unwrap()
}

pub fn bytes_to_hex(s: &[u8]) -> String {
    hex::encode(s)
}

pub fn get_from_args(pos: usize) -> Result<String> {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() > pos, "invalid argument position");

    Ok(args[pos].clone())
}

pub fn read_line_from_file(file_name: String, line: u32) -> Result<String> {
    let file = File::open(file_name)?;
    let mut reader = BufReader::new(file);

    let mut text = String::new();

    for _n in 0..line {
        text.clear();
        reader.read_line(&mut text)?;
    }
    
    if let Some('\n')=text.chars().next_back() {
        text.pop();
    }
    if let Some('\r')=text.chars().next_back() {
        text.pop();
    }
    Ok(text)
}

pub fn read_file(file_name: String) -> Result<String> {
    let text = read_to_string(file_name)?;

    Ok(text)
}

pub fn check_credentials(username: String, password: String) -> bool{
    let hashed_pw = bytes_to_hex(&(ninja_crypt::hash(&password, 128)));

    let mut file_name = String::from("./.config/");
    file_name.push_str(&username);

    let db_pw = read_line_from_file(file_name, 1).unwrap();

    hashed_pw == db_pw
}

pub fn write_to_new_file(file_name: String, content: String) {
    let mut file = File::create(file_name)
        .unwrap_or_else(| err | {
            eprintln!("Could not create entry file: {}", err);
            process::exit(1);
        });
    
    file.write_all(content.as_bytes())
        .unwrap_or_else(| err | {
            eprintln!("Could not write to user file: {}", err);
            process::exit(1);
        });
}
