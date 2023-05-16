extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;

use bytes::{Buf, BufMut};
use std::str::from_utf8;
use prost::Message as ProtoMessage;

use sha2::{Sha256, Digest};

use libsecp256k1::*;
use crate::{sign, verify, SecretKey, PublicKey, Signature, Message, PublicKeyFormat};

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
pub fn verify_transaction(s:String) -> String {
    if s.len() == 0 {
        return "".to_string()
    }
    if let Ok(request) = hex::decode(s) {
        if let Ok(Some(tx_with_data)) = decode::<pb::TransactionWithData>(&request) {
            if let Some(tx) = tx_with_data.transaction {
                if let Ok(ok) = _verify_tx(tx) {
                    if ok {
                        return "true".to_string();
                    }
                    return "false".to_string();
                }
            }
        }
    }
    return "".to_string();
}

#[test]
fn verify_test(){
    let tx_with_data = "670aa7010865121602002475880261f488a86cc3788af127009c46d162d2180220c0843d3243020004743275b498e96ac0e123d9bdbef11ebd839f3fd4bf9b728799b86ca1d63d5ab2bccbd4a6375c858f795585834354dd50deda0345c95b3d9e38557a4e467eaf673a40b2443b4eac2a882502aa13fdf41bb4056dd200cb852964bf1ac3b8cd74508f7e4b93cc59e7656e65e30fec760da10ee0bb47f25fa54328d68f7ecbcf9616529412a6100805228a01790a42087910051a1602002475880261f488a86cc3788af127009c46d162d220022a207d2f1164015f5f1be3d0400535211fc892123bff94886ff33c73090d5388366830014a43020004743275b498e96ac0e123d9bdbef11ebd839f3fd4bf9b728799b86ca1d63d5ab2bccbd4a6375c858f795585834354dd50deda0345c95b3d9e38557a4e467eaf672243790a40087910051a160200c287b1266732495fe8c93ce3ba631597153fdd912a2087b113f9c094c26d482c122f3f7cf7295aec44b2fcd05fbff058562798cd949330052a72910a012a126ca46464617461505e452700000000003600000000000000646e616d65784034384131384634434235454133333046423943304535303736314146423432453643413436344433463534354133323335423133433335323236423641314335647265667301666368756e6b73802a62910a012f125ca4646461746140646e616d65784034384131384634434235454133333046423943304535303736314146423432453643413436344433463534354133323335423133433335323236423641314335647265667301666368756e6b73802a63910a023533125ca4646461746140646e616d65784034384131384634434235454133333046423943304535303736314146423432453643413436344433463534354133323335423133433335323236423641314335647265667301666368756e6b73802a45910a201a6562590ef19d1045d06c4055742d38288e9e6dcd71ccde5cee80f1d5a774eb1220a46464617461423530646e616d6563676173647265667301666368756e6b73802aec05910a2048a18f4cb5ea330fb9c0e50761afb42e6ca464d3f545a3235b13c35226b6a1c512c605a46464617461590180a3636b6579582087744755614fda4d317a576469bb3a1cf11c6c032f9bf69973a901fb4aa1c1cb646e616d6565746f6b656e6567726f7570f5a3636b65795820d75fd5c44bb71004aa975eeabcdeb0cdfeae39ad002f0fae4fa7403a128ccdff646e616d6564636f64656567726f7570f5a3636b65795820ade71232335354f5052572d2bc7d8d14d77c458ac8fe97586dd67714e71cb4ba646e616d6568636f6e74726163746567726f7570f5a3636b65795820098e2d6e8c0d45b74cefebcfd03341bf1a06ebf1ad3ad42746a3ec4e4fab0dd3646e616d6564757365726567726f7570f5a3636b6579582067791b4b6aac06d0e71fc3b51165d7ac672dfa1d1bdd560c80b58c26a7c61229646e616d65782e6574682e3078633238374231323636373332343935466538633933434533426136333135393731353366646439316567726f7570f5a3636b65795820a54b1da2ec02d04594c0a38299e88374ee31b3bf3e737edb2054de215793c13e646e616d6564706167656567726f7570f5646e616d65612f647265667301666368756e6b7386a2636b6579582087744755614fda4d317a576469bb3a1cf11c6c032f9bf69973a901fb4aa1c1cb676e657874506f731839a2636b65795820d75fd5c44bb71004aa975eeabcdeb0cdfeae39ad002f0fae4fa7403a128ccdff676e657874506f731871a2636b65795820ade71232335354f5052572d2bc7d8d14d77c458ac8fe97586dd67714e71cb4ba676e657874506f7318ada2636b65795820098e2d6e8c0d45b74cefebcfd03341bf1a06ebf1ad3ad42746a3ec4e4fab0dd3676e657874506f7318e5a2636b6579582067791b4b6aac06d0e71fc3b51165d7ac672dfa1d1bdd560c80b58c26a7c61229676e657874506f73190148a2636b65795820a54b1da2ec02d04594c0a38299e88374ee31b3bf3e737edb2054de215793c13e676e657874506f731901802adb01910a204e7a559722d10bbb07ebc7f841099f20a4d822b8b243e1eec155d77ea5c6587312b501a464646174615863a3636b65795820bc1a5a9a25b00533f28f664b9836c3e31f224b4ec4901ac2877b846d9436b0df646e616d65782e6574682e3078633238374231323636373332343935466538633933434533426136333135393731353366646439316567726f7570f5646e616d65657374617465647265667301666368756e6b7381a2636b65795820bc1a5a9a25b00533f28f664b9836c3e31f224b4ec4901ac2877b846d9436b0df676e657874506f7318632adb01910a2067791b4b6aac06d0e71fc3b51165d7ac672dfa1d1bdd560c80b58c26a7c6122912b501a464646174615839a3636b657958204e7a559722d10bbb07ebc7f841099f20a4d822b8b243e1eec155d77ea5c65873646e616d656573746174656567726f7570f5646e616d65782e6574682e307863323837423132363637333234393546653863393343453342613633313539373135336664643931647265667301666368756e6b7381a2636b657958204e7a559722d10bbb07ebc7f841099f20a4d822b8b243e1eec155d77ea5c65873676e657874506f7318392ad901910a20bc1a5a9a25b00533f28f664b9836c3e31f224b4ec4901ac2877b846d9436b0df12b301a464646174615837a3636b657958201a6562590ef19d1045d06c4055742d38288e9e6dcd71ccde5cee80f1d5a774eb646e616d65636761736567726f7570f4646e616d65782e6574682e307863323837423132363637333234393546653863393343453342613633313539373135336664643931647265667301666368756e6b7381a2636b657958201a6562590ef19d1045d06c4055742d38288e9e6dcd71ccde5cee80f1d5a774eb676e657874506f7318372a45910a20d59eced1ded07f84c145592f65bdf854358e009c5cd705f5215bf18697fed1031220a46464617461423430646e616d6563676173647265667301666368756e6b738018aee08ba306".to_string();
    let ret = verify_transaction(tx_with_data);
    assert_eq!(ret, "true".to_string());
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