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
    if let Ok((t, pk)) = get_public(&s) {
        let key = encode_key(t, pk.serialize().to_vec());
        return hex::encode(key);
    }
    return "".to_string();
}

#[wasm_bindgen]
pub fn decode_public_key(s: String) -> String {
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
    if let Ok(b) = hex::decode(s) {
        if let Ok(Some(user_info)) = decode::<pb::UserInfo>(&b) {
            if let Some(address) = decode_address(&user_info.account) {
                if let Some(data) = user_info.data {
                    return address + "," + &hex::encode(&user_info.key) + "," + &hex::encode(&user_info.nonce) + "," + &hex::encode(&data.hash);
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
    
    let (_, _, pub_key, address) = get_secret(&secret).unwrap();
    let public = "eth.".to_owned() + &hex::encode(pub_key.serialize());

    // println!("{}", &secret);
    // println!("{}", &public);
    // println!("{}", &address);

    return ["ETH", &address, &secret, &public].join(",");

    // let mut mm = HashMap::<String, pb::Data>::new();
    // mm.insert("type".to_string(), pb::Data {
    //     bytes: encode_string("ETH".to_string()),
    // });
    // mm.insert("address".to_string(), pb::Data{
    //     bytes: encode_string(address),
    // });
    // mm.insert("private".to_string(), pb::Data{
    //     bytes: encode_string(secret),
    // });
    // mm.insert("public".to_string(), pb::Data{
    //     bytes: encode_string(public),
    // });
    // let nm = pb::DataMap{
    //     map: mm,
    // };
    // let rb = encode(CORE_DATA_MAP, &nm).unwrap();
    // let reply = hex::encode(rb);
    // return reply;
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
    let blob = sign_transaction("410a390a0466726f6d12310a2f3e6574682e3078366461363861306335644141453037313541453662363246303066353438413243363938316332660a100a0367617312090a073e3230303030300aca070a077061796c6f616412be070abb07410ab7070a047061676512ae070aab07410a97070a0464617461128e070a8b073e3530346230333034313430303030303030383030653862393933353631633230366633323162303130303030623030323030303030613030316330303639366536343635373832653638373436643663353535343039303030333833303534303634343531333435363437353738306230303031303466373031303030303034313430303030303039353532346234666334323031306265656661666330333935626430363838633037363836323763356366356230396137386134333036623637393735326134373433376664663735326262396266386361633635656638363639386566393163306338393362626337646265356562643333646162353365336361383531633831333965646466313461303837373263313938616335316462623163383635383334393333353365626438363135326630626337633238616536313366373265343337326361323533343061366635633065613838326230353563616366343736626365306639383061663265356533376138363034626238306236643463633033323237613163666165336262326139353631366233306338626366653639343931613734346461313539646431306564353339336633623538323534613065636231373461633836653432393036326561613735393637323238356334626136383134303834373935383863313838373532376436656633646336613162386530353766633932616633623238613539386138666664326631386162636365333034333938363130656464333863613066333134373531623964363663376530383865326266613434366534653832366632646665653234623731353830643539623537366438356235386461333262323061373430383233336462376466626464333130663263373337616465643164633239346334343530366431363866323766363434636436333936623563643030663530346230313032316530333134303030303030303830306538623939333536316332303666333231623031303030306230303230303030306130303138303030303030303030303031303030303030613438313030303030303030363936653634363537383265363837343664366335353534303530303033383330353430363437353738306230303031303466373031303030303034313430303030303035303462303530363030303030303030303130303031303035303030303030303566303130303030303030300a0e0a046e616d6512060a043e6c69620a510a0673656372657412470a453e6574682e626565633965633631633137623034636239653461396237303137653734396639323833356532373433653935663934636465323138643636376231343130390a100a0873657175656e636512040a023e380a370a02746f12310a2f3e6574682e3078423561316432653932353231323439616230373933343130393543646165343443643439393837370a0f0a0576616c756512060a043e313030".to_string());
    assert_eq!(blob, "650865121602006da68a0c5daae0715ae6b62f00f548a2c6981c2f180820c09a0c2a160200b5a1d2e92521249ab079341095cdae44cd49987732f6030af3030a20db3d5388e898957eaf4fa2ca95939fc0969236fd168b8607a1f9a58ccb00bf1d12ce03930a036c696212c503504b0304140000000800e8b993561c206f321b010000b00200000a001c00696e6465782e68746d6c5554090003830540644513456475780b000104f7010000041400000095524b4fc42010beefafc0395bd0688c0768627c5cf5b09a78a4306b679752a47437fdf752bb9bf8cac65ef86698ef91c0c893bbc7dbe5ebd33dab53e3ca851c8139eddf14a08772c198ac51dbb1c86583493353ebd86152f0bc7c28ae613f72e4372ca25340a6f5c0ea882b055cacf476bce0f980af2e5e37a8604bb80b6d4cc03227a1cfae3bb2a95616b30c8bcfe69491a744da159dd10ed5393f3b58254a0ecb174ac86e429062eaa759672285c4ba681408479588c1887527d6ef3dc6a1b8e057fc92af3b28a598a8ffd2f18abcce304398610edd38ca0f314751b9d66c7e088e2bfa446e4e826f2dfee24b71580d59b576d85b58da32b20a7408233db7dfbdd310f2c737aded1dc294c44506d168f27f644cd6396b5cd00f504b01021e03140000000800e8b993561c206f321b010000b00200000a0018000000000001000000a48100000000696e6465782e68746d6c55540500038305406475780b000104f70100000414000000504b05060000000001000100500000005f01000000003a43020004d33a199d322fafd28867e3b9fb2f5ac081d56cff1ae803635730e1d01b77d837d9ee578346dd88b68d21b9a61b8f1efe9b2574f08b4a471f864fa7ea7a29185c4240340d71af871306d7e75122605be808ae66c5bb09c94808961d575b62e90f1cb74c70533edc5f3f14f97923a5a40e712f21718f29e51b7a3068e4c336435d35bf");
}

#[test]
fn sign_contract_test() {
    let blob = sign_transaction("410a390a0466726f6d12310a2f3e6574682e3078366233396261383643614236333641373830633964443638643439423046343933373933416138330a100a0367617312090a073e3530303030300ac5010a077061796c6f616412b9010ab601410ab2010a08636f6e747261637412a5010aa201410a3c0a076163636f756e7412310a2f3e6574682e3078423561316432653932353231323439616230373933343130393543646165343443643439393837370a150a066d6574686f64120b0a093e72656769737465720a4a0a06706172616d7312400a3e3e3a737472696e672c6574682e3078366233396261383643614236333641373830633964443638643439423046343933373933416138333a737472696e670a510a0673656372657412470a453e6574682e643435343464646330323465656263386663366435366137343336373232343266353639653265626563373232303231393561393835323234333532343538300a100a0873657175656e636512040a023e350a370a02746f12310a2f3e6574682e307842356131643265393235323132343961623037393334313039354364616534344364343939383737".to_string());
    assert_eq!(blob, "650865121602006b39ba86cab636a780c9dd68d49b0f493793aa83180520a0c21e2a160200b5a1d2e92521249ab079341095cdae44cd499877327d0a7b0a20bed09f277ae78741ff108f5458588648a52c681526a28d9755e3bd1538115fad12578e0a160200b5a1d2e92521249ab079341095cdae44cd499877220872656769737465722a013e2a2f3e6574682e3078366233396261383643614236333641373830633964443638643439423046343933373933416138333a43020004d221070e1171316f197d213e22092bcc33103f24a49ac1c8da2f02bcb7ae93c21a81580d206e361b2575da4552b44620cffde9ab1172ecaaddc4adaef9a1d9cd4240740a46a6e28a8c0db85d52bd5e2e81231607b9afaeb01c276a1d8953bdf61e7e53bfd80d6cb5846516296cbe1ed47cb358bf95ee3df737b76db0f0c76f16733e".to_string());
}


#[wasm_bindgen]
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[test]
fn add_test() {
    assert_eq!(1+1, add(1, 1));
}