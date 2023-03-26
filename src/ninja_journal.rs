use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::fs::remove_file;
use std::fs::read_to_string;

// use std::io::Read;
use std::process;
use std::process::Command;

// use hex_literal;

use crate::ninja_crypt;
use crate::ninja_utils;



pub fn run() {

    let command = ninja_utils::get_from_args(1)
    .unwrap_or_else(| err | {
        eprintln!("You need to pass a command: {}", err);
        process::exit(1);
    });

    if command == "setup" {
        println!("You want to setup the user");
        setup();
    }
    else if command == "add" {
        println!("You want to add an entry");
        let title = ninja_utils::get_from_args(2)
        .unwrap_or_else(| err | {
            eprintln!("You need to pass a title for the entry: {}", err);
            process::exit(1);
        });
        add_entry(title);
    }
    else if command == "del" {
        println!("You want to delete an entry");
    }
    else if command == "list" {
        println!("You want to list entries");
    }
    else if command == "read" {
        println!("You want to read an entry");
        let title = ninja_utils::get_from_args(2)
        .unwrap_or_else(| err | {
            eprintln!("You need to pass a title for the entry: {}", err);
            process::exit(1);
        });
        read_entry(title);
    }
    else {
        println!("Invalid Command!");
    }
}

fn setup() {
    let username = ninja_utils::ask_user_input("username: ");
    let password1 = ninja_utils::ask_user_secret_input("password: ");
    let password2 = ninja_utils::ask_user_secret_input("repeat password: ");

    if !password1.eq(&password2) {
        eprintln!("The passwords do not match");
        process::exit(1);
    }

    let mut user_file_path = String::from(".config/");
    user_file_path.push_str(&username);

    let mut file = File::create(user_file_path)
        .unwrap_or_else(| err | {
            eprintln!("Could not create user file: {}", err);
            process::exit(1);
        });
    let hashed_password = ninja_crypt::hash(&password1, 128);
    let mut iv = [0; 32];
    ninja_utils::get_rand_bytes(&mut iv)
        .unwrap_or_else(| err | {
            eprintln!("Could generate random iv: {}", err);
            process::exit(1);
        });

    file.write_all(ninja_utils::bytes_to_hex(&hashed_password).as_bytes())
        .unwrap_or_else(| err | {
            eprintln!("Could not write to user file: {}", err);
            process::exit(1);
        });
    file.write(b"\n")
        .unwrap_or_else(| err | {
            eprintln!("Could not write to user file: {}", err);
            process::exit(1);
        });
    file.write(ninja_utils::bytes_to_hex(&iv).as_bytes())
        .unwrap_or_else(| err | {
            eprintln!("Could not write to user file: {}", err);
            process::exit(1);
        });
}

fn add_entry(title: String) {
    let username = ninja_utils::ask_user_input("username: ");
    let password = ninja_utils::ask_user_secret_input("password: ");

    if !ninja_utils::check_credentials(username.clone(), password.clone()) {
        print!("Wrong password or username!");
        process::exit(1);
    }

    // get editor
    let editor = env::var("EDITOR")
        .unwrap_or_else(| err | {
            eprintln!("EDITOR environment variable not set: {}", err);
            process::exit(1);
        });

    // create temp file
    let mut temp_file_path = env::current_dir()
        .unwrap_or_else(| err | {
            eprintln!("Could not define temporary location for new entry: {}", err);
            process::exit(1);
        });
    temp_file_path.push(".tmp/temp_entry.txt");
    if let Err(e) = File::create(&temp_file_path) {
        eprintln!("Could not create file: {}", e);
        process::exit(1);
    }

    // open editor and wait for the user to finish the entry
    if let Err(e) = Command::new(editor).arg(&temp_file_path).status() {
        eprintln!("Editor error: {}", e);
        remove_file(temp_file_path).unwrap();
        process::exit(1);
    }

    // encrypt the temp file and save it in the correct location
    let temp_file_content = read_to_string(temp_file_path.clone())
        .unwrap_or_else(| err | {
            eprintln!("Could not read temporary file: {}", err);
            remove_file(temp_file_path.clone()).unwrap();
            process::exit(1);
        });

    let mut file_name = String::from("./.config/");
    file_name.push_str(&username);
    let iv = ninja_utils::read_line_from_file(file_name, 2).unwrap();

    let iv = hex::decode(iv).unwrap();
    let secret = ninja_crypt::hash(&password, 16);

    let encrypted_entry = ninja_crypt::encrypt_entry(&secret, &iv, temp_file_content);
    let entry_file_name = title.replace(" ", "_");

    let mut entry_file_path = String::from("./.entries/");
    entry_file_path.push_str(&entry_file_name);

    ninja_utils::write_to_new_file(entry_file_path, encrypted_entry);

    remove_file(temp_file_path).unwrap();
}

fn read_entry(title: String) {
    let username = ninja_utils::ask_user_input("username: ");
    let password = ninja_utils::ask_user_secret_input("password: ");

    if !ninja_utils::check_credentials(username.clone(), password.clone()) {
        print!("Wrong password or username!");
        process::exit(1);
    }

    let mut file_name = String::from("./.config/");
    file_name.push_str(&username);
    let iv = ninja_utils::read_line_from_file(file_name, 2).unwrap();

    let iv = hex::decode(iv).unwrap();
    let secret = ninja_crypt::hash(&password, 16);

    let entry_file_name = title.replace(" ", "_");
    let mut entry_file_path = String::from("./.entries/");
    entry_file_path.push_str(&entry_file_name);
    let encrypted_entry = ninja_utils::read_file(entry_file_path).unwrap();

    let decrypted_entry = ninja_crypt::decrypt_entry(&secret, &iv, encrypted_entry);

    println!("{}", decrypted_entry);
}
