extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;

use bytes::{Buf, BufMut};
use std::str::from_utf8;
use prost::Message as ProtoMessage;

use sha2::{Sha256, Digest};

use libsecp256k1::*;
use crate::{sign, SecretKey, PublicKey, Message, PublicKeyFormat};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, AeadCore
};

mod pb {
    include!("./pb.rs");
}
include!("./core.rs");
include!("./tx.rs");

#[wasm_bindgen]
pub fn generate_key() -> String {
    let key = _generate_aes_key();
    return hex::encode(&key);
}

#[wasm_bindgen]
pub fn generate_nonce() -> String {
    let nonce = _generate_aes_nonce();
    return hex::encode(&nonce);
}

#[wasm_bindgen]
pub fn encode_public_key(s: String) -> String {
    if s.len() == 0 {
        return "".to_string()
    }
    if let Ok((t, pk)) = get_public(&s) {
        let key = encode_key(t, pk.serialize().to_vec());
        return hex::encode(key);
    }
    return "".to_string();
}

#[wasm_bindgen]
pub fn decode_public_key(s: String) -> String {
    if s.len() == 0 {
        return "".to_string()
    }
    if let Ok(b) = hex::decode(s) {
        let (t, key) = decode_key(b);
        let key_type = get_key(t);
        return key_type.to_owned() + "." + &hex::encode(key);
    }
    return "".to_string();
}

#[test]
pub fn public_key_test() {
    let pk = "020004d33a199d322fafd28867e3b9fb2f5ac081d56cff1ae803635730e1d01b77d837d9ee578346dd88b68d21b9a61b8f1efe9b2574f08b4a471f864fa7ea7a29185c";
    let s = decode_public_key(pk.to_string());
    let t = encode_public_key(s);
    assert_eq!(pk, t);
}

#[wasm_bindgen]
pub fn encode_user_info(s: String) -> String {
    if s.len() == 0 {
        return "".to_string()
    }
    if let Ok(b) = hex::decode(s) {
        if let Ok(Some(m)) = decode::<pb::DataMap>(&b) {
            if let Ok(user_info) = _get_user_info(m, false) {
                if let Ok(user_bytes) = encode(CORE_USER_INFO, &user_info) {
                    return hex::encode(user_bytes);
                }
            }
        }
    }
    return "".to_string();
}

#[wasm_bindgen]
pub fn decode_user_info(s: String) -> String {
    if s.len() == 0 {
        return "".to_string()
    }
    if let Ok(b) = hex::decode(s) {
        if let Ok(Some(user_info)) = decode::<pb::UserInfo>(&b) {
            if let Some(account_info) = user_info.account {
                let data_account = decode_address(&account_info.data);
                let code_account = decode_address(&account_info.code);
                let data_string = _get_option_string(data_account);
                let code_string = _get_option_string(code_account);
                if let Some(data) = user_info.data {
                    return data_string + "," + &code_string + "," + &hex::encode(&user_info.key) + "," + &hex::encode(&user_info.nonce) + "," + &hex::encode(&data.hash);
                }
            }
        }
    }
    return "".to_string();
}

#[wasm_bindgen]
pub fn encrypt_data(key:String, nonce:String, msg:String) -> String {
    if let Ok(k) = hex::decode(key) {
        if let Ok(n) = hex::decode(nonce) {
            if let Ok(m) = hex::decode(msg) {
                if let Ok(ciphertext) = _aes_encrypt(&k, &n, m.as_ref()) {
                    return hex::encode(ciphertext);
                }
            }
        }
    }
    return "".to_string();
}

#[wasm_bindgen]
pub fn decrypt_data(key:String, nonce:String, msg:String) -> String {
    if let Ok(k) = hex::decode(key) {
        if let Ok(n) = hex::decode(nonce) {
            if let Ok(m) = hex::decode(msg) {
                if let Ok(dephertext) = _aes_decrypt(&k, &n, m.as_ref()) {
                    return hex::encode(dephertext);
                }
            }
        }
    }
    return "".to_string();
}

#[wasm_bindgen]
pub fn encapsulate(secret:String, peer_public:String) -> String {
    if secret.len() == 0 || peer_public.len() == 0 {
        return "".to_string()
    }
    if let Ok((_, priv_key, _, _)) = get_secret(&secret) {
        if let Ok((_, pub_key)) = get_public(&peer_public) {
            if let Ok(r) = _encapsulate(&priv_key, &pub_key) {
                return hex::encode(r);
            }
        }
    }
    return "".to_string();
}

#[wasm_bindgen]
pub fn decapsulate(pub_key:String, peer_secret:String) -> String {
    if pub_key.len() == 0 || peer_secret.len() == 0 {
        return "".to_string()
    }
    if let Ok((_, pub_key)) = get_public(&pub_key) {
        if let Ok((_, priv_key, _, _)) = get_secret(&peer_secret) {
            if let Ok(r) = _decapsulate(&pub_key, &priv_key) {
                return hex::encode(r);
            }
        }
    }
    return "".to_string();
}

#[wasm_bindgen]
pub fn encrypt(public_key:String, msg:String) -> String {
    if public_key.len() == 0 {
        return "".to_string()
    }
    if let Ok((_, pub_key)) = get_public(&public_key) {
        if let Ok(m) = hex::decode(msg) {
            if let Ok(r) = _encrypt(&pub_key, &m) {
                return hex::encode(r);
            }
        }
    }
    
    return "".to_string();
}

#[wasm_bindgen]
pub fn decrypt(secret:String, msg:String) -> String {
    if secret.len() == 0 {
        return "".to_string()
    }
    if let Ok((_, priv_key, _, _)) = get_secret(&secret) {
        if let Ok(m) = hex::decode(msg) {
            if let Ok(r) = _decrypt(&priv_key, &m) {
                return hex::encode(r);
            }
        }
    }
    return "".to_string();
}

#[test]
fn encrypt_test(){
    let msg = hex::encode(b"message");
    let er = encrypt("eth.04d33a199d322fafd28867e3b9fb2f5ac081d56cff1ae803635730e1d01b77d837d9ee578346dd88b68d21b9a61b8f1efe9b2574f08b4a471f864fa7ea7a29185c".to_string(), msg.to_string());
    let dr = decrypt("eth.beec9ec61c17b04cb9e4a9b7017e749f92835e2743e95f94cde218d667b14109".to_string(), er);
    assert_eq!(msg, dr);

    let r = generate_key();
    let n = generate_nonce();
    let m = hex::encode(b"plaintext message");
    let em = encrypt_data(r.to_string(), n.to_string(), m.to_string());
    let dm = decrypt_data(r.to_string(), n.to_string(), em);
    assert_eq!(m, dm);
}

#[wasm_bindgen]
pub fn generate_account(phrase:String) -> String {
    let bs = phrase.as_bytes();
    let hash = keccak256(&bs.to_vec());

    let secret = "eth.".to_owned() + &hex::encode(&hash);
    return import_account(secret);
}

#[wasm_bindgen]
pub fn import_account(secret:String) -> String {
    let (_, _, pub_key, address) = get_secret(&secret).unwrap();
    let public = "eth.".to_owned() + &hex::encode(pub_key.serialize());

    // println!("{}", &secret);
    // println!("{}", &public);
    // println!("{}", &address);

    return ["ETH", &address, &secret, &public].join(",");
}

#[wasm_bindgen]
pub fn sign_transaction(s:String) -> String {
    if s.len() == 0 {
        return "".to_string()
    }
    match hex::decode(s) {
        Ok(request) => {
            match decode(&request) {
                Ok(r) => match r {
                    Some(m) => {
                        match _sign_tx(m) {
                            Ok(ret) => {
                                return ret;
                            }
                            Err(err) => {
                                println!("error: {:?}", err);
                                return "".to_string()
                            }
                        }
                    }
                    _ => {
                        return "".to_string()
                    }
                }
                _ => {
                    return "".to_string()
                }
            }
        }
        _ => {
            return "".to_string()
        }
    }
}

#[test]
fn data_test() {
    assert_eq!(CORE_DATA_INT32, get_type("int32"));
}

#[test]
fn generate_test(){
    let ret = generate_account("masterpassphrase".to_string());
    assert_eq!(ret, "ETH,eth.0x6da68a0c5dAAE0715AE6b62F00f548A2C6981c2f,eth.beec9ec61c17b04cb9e4a9b7017e749f92835e2743e95f94cde218d667b14109,eth.04d33a199d322fafd28867e3b9fb2f5ac081d56cff1ae803635730e1d01b77d837d9ee578346dd88b68d21b9a61b8f1efe9b2574f08b4a471f864fa7ea7a29185c")
}

#[test]
fn sign_tx_test() {
    let blob = sign_transaction("".to_string());
    assert_eq!(blob, "");
}

#[test]
fn sign_contract_test() {
    let blob = sign_transaction("".to_string());
    assert_eq!(blob, "".to_string());
}

#[wasm_bindgen]
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[test]
fn add_test() {
    assert_eq!(1+1, add(1, 1));
}