use tiny_keccak::{Hasher, Keccak};
use libsecp256k1::{util::FULL_PUBLIC_KEY_SIZE, Error as SecpError};
use hkdf::Hkdf;

const EMPTY_BYTES: [u8; 0] = [];
const NONCE_SIZE: usize = 12;

const CORE_DATA:u8  = 11;

const CORE_DATA_NULL:u8    = 50;
const CORE_DATA_BOOLEAN:u8 = 51;

const CORE_DATA_INT8:u8  = 52;
const CORE_DATA_INT16:u8 = 53;
const CORE_DATA_INT32:u8 = 54;
const CORE_DATA_INT64:u8 = 55;

const CORE_DATA_UINT8:u8  = 56;
const CORE_DATA_UINT16:u8 = 57;
const CORE_DATA_UINT32:u8 = 58;
const CORE_DATA_UINT64:u8 = 59;

const CORE_DATA_FLOAT32:u8 = 60;
const CORE_DATA_FLOAT64:u8 = 61;

const CORE_DATA_STRING:u8 = 62;
const CORE_DATA_BYTES:u8  = 63;

const CORE_DATA_LIST:u8 = 64;
const CORE_DATA_MAP:u8  = 65;

const CORE_TRANSACTION:u8 = 101;

const CORE_CONTRACT_INFO:u8 = 142;
const CORE_META_INFO:u8 = 143;
const CORE_TOKEN_INFO:u8 = 144;
const CORE_PAGE_INFO:u8 = 147;
const CORE_CODE_INFO:u8 = 148;
const CORE_USER_INFO:u8 = 149;

// KeyType
const ETH:u16 = 2;

fn get_key(t: u16) -> &'static str {
    match t {
        ETH => {
            return "eth";
        }
        _ => {
            return "";
        }
    }
}

fn get_info(meta: u8) -> &'static str {
    match meta {
        CORE_DATA => {
            return "data";
        }
        CORE_DATA_NULL => {
            return "data_null";
        }
        CORE_DATA_BOOLEAN => {
            return "data_boolean";
        }
        CORE_DATA_INT8 => {
            return "data_int8";
        }
        CORE_DATA_INT16 => {
            return "data_int16";
        }
        CORE_DATA_INT32 => {
            return "data_int32";
        }
        CORE_DATA_INT64 => {
            return "data_int64";
        }
        CORE_DATA_UINT8 => {
            return "data_uint8";
        }
        CORE_DATA_UINT16 => {
            return "data_uint16";
        }
        CORE_DATA_UINT32 => {
            return "data_uint32";
        }
        CORE_DATA_UINT64 => {
            return "data_uint64";
        }
        CORE_DATA_FLOAT32 => {
            return "data_float32";
        }
        CORE_DATA_FLOAT64 => {
            return "data_float64";
        }
        CORE_DATA_STRING => {
            return "data_string";
        }
        CORE_DATA_BYTES => {
            return "data_bytes";
        }
        CORE_DATA_LIST => {
            return "data_list";
        }
        CORE_DATA_MAP => {
            return "data_map";
        }
        _ => {
            return "";
        }
    }
}

fn get_type(t: &str) -> u8 {
    match t {
        "boolean" => {
            return CORE_DATA_BOOLEAN;
        }
        "int8" => {
            return CORE_DATA_INT8;
        }
        "int16" => {
            return CORE_DATA_INT16;
        }
        "int32" => {
            return CORE_DATA_INT32;
        }
        "int64" => {
            return CORE_DATA_INT64;
        }
        "uint8" => {
            return CORE_DATA_UINT8;
        }
        "uint16" => {
            return CORE_DATA_UINT16;
        }
        "uint32" => {
            return CORE_DATA_UINT32;
        }
        "uint64" => {
            return CORE_DATA_UINT64;
        }
        "float32" => {
            return CORE_DATA_FLOAT32;
        }
        "float64" => {
            return CORE_DATA_FLOAT64;
        }
        "string" => {
            return CORE_DATA_STRING;
        }
        "bytes" => {
            return CORE_DATA_BYTES;
        }
        "list" => {
            return CORE_DATA_LIST;
        }
        "map" => {
            return CORE_DATA_MAP;
        }
        _ => {
            return 0;
        }
    }
}

fn get_from_string(meta: u8, s: &str) -> Result<Vec<u8>, Error> {
    match meta {
        CORE_DATA_BOOLEAN => {
            match s.parse::<bool>() {
                Ok(b) => {
                    return Ok(encode_boolean(b));
                }
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err))
                }
            }
        }
        CORE_DATA_INT8 => {
            match s.parse::<i8>() {
                Ok(v) => {
                    return Ok(encode_i8(v));
                }
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err))
                }
            }
        }
        CORE_DATA_INT16 => {
            match s.parse::<i16>() {
                Ok(v) => {
                    return Ok(encode_i16(v));
                }
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err))
                }
            }
        }
        CORE_DATA_INT32 => {
            match s.parse::<i32>() {
                Ok(v) => {
                    return Ok(encode_i32(v));
                }
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err))
                }
            }
        }
        CORE_DATA_INT64 => {
            match s.parse::<i64>() {
                Ok(v) => {
                    return Ok(encode_i64(v));
                }
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err))
                }
            }
        }
        CORE_DATA_UINT8 => {
            match s.parse::<u8>() {
                Ok(v) => {
                    return Ok(encode_u8(v));
                }
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err))
                }
            }
        }
        CORE_DATA_UINT16 => {
            match s.parse::<u16>() {
                Ok(v) => {
                    return Ok(encode_u16(v));
                }
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err))
                }
            }
        }
        CORE_DATA_UINT32 => {
            match s.parse::<u32>() {
                Ok(v) => {
                    return Ok(encode_u32(v));
                }
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err))
                }
            }
        }
        CORE_DATA_UINT64 => {
            match s.parse::<u64>() {
                Ok(v) => {
                    return Ok(encode_u64(v));
                }
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err))
                }
            }
        }
        CORE_DATA_FLOAT32 => {
            match s.parse::<f32>() {
                Ok(v) => {
                    return Ok(encode_f32(v));
                }
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err))
                }
            }
        }
        CORE_DATA_FLOAT64 => {
            match s.parse::<f64>() {
                Ok(v) => {
                    return Ok(encode_f64(v));
                }
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err))
                }
            }
        }
        CORE_DATA_STRING => {
            return Ok(encode_string(String::from(s)));
        }
        CORE_DATA_BYTES => {
            match hex::decode(s) {
                Ok(bs) => {
                    return Ok(encode_bytes(&bs));
                }
                _ => {
                    return Err(Error::new(ErrorKind::InvalidData, "error bytes"));
                }
            }
        }
        CORE_DATA_LIST => {
            match hex::decode(s) {
                Ok(bs) => {
                    return Ok(encode_data(CORE_DATA_LIST, &bs));
                }
                _ => {
                    return Err(Error::new(ErrorKind::InvalidData, "error data list"));
                }
            }
        }
        CORE_DATA_MAP => {
            match hex::decode(s) {
                Ok(bs) => {
                    return Ok(encode_data(CORE_DATA_MAP, &bs));
                }
                _ => {
                    return Err(Error::new(ErrorKind::InvalidData, "error data map"));
                }
            }
        }
        _ => {
            return Err(Error::new(ErrorKind::InvalidData, "unknown data type"));
        }
    }
}

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
}

fn decode<T: ProtoMessage + std::default::Default>(data: &Vec<u8>) -> Result<Option<T>, Error> {
    if data.len() == 0 {
        return Err(Error::new(ErrorKind::InvalidData, "empty"));
    }
    let mut rdata = data.as_slice();
    let meta = rdata.get_u8();
    match meta {
        CORE_DATA => {
            match ProtoMessage::decode(rdata.chunk()) {
                Ok(m) => {
                    return Ok(Some(m));
                }, 
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err));
                },
            };
        }
        CORE_DATA_NULL => {
            return Ok(None);
        }
        CORE_DATA_LIST => {
            match ProtoMessage::decode(rdata.chunk()) {
                Ok(m) => {
                    return Ok(Some(m));
                }, 
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err));
                },
            };
        }
        CORE_DATA_MAP => {
            match ProtoMessage::decode(rdata.chunk()) {
                Ok(m) => {
                    return Ok(Some(m));
                }, 
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err));
                },
            };
        }
        CORE_USER_INFO => {
            match ProtoMessage::decode(rdata.chunk()) {
                Ok(info) => {
                    return Ok(Some(info));
                }, 
                Err(err) => {
                    return Err(Error::new(ErrorKind::InvalidData, err));
                },
            };
        }
        _ => {
            return Err(Error::new(ErrorKind::InvalidData, "unknown data type"));
        }
    }
}

fn decode_i32(data: &pb::Data) -> Option<i32> {
    if data.bytes.len() > 0 {
        let mut idata = data.bytes.as_slice();
        let meta = idata.get_u8();
        match meta {
            CORE_DATA_INT32 => {
                return Some(idata.get_i32_le());
            },
            _ => {
                return None;
            }
        }
    }
    return None;
}

fn decode_i64(data: &pb::Data) -> Option<i64> {
    if data.bytes.len() > 0 {
        let mut idata = data.bytes.as_slice();
        let meta = idata.get_u8();
        match meta {
            CORE_DATA_INT64 => {
                return Some(idata.get_i64_le());
            },
            _ => {
                return None;
            }
        }
    }
    return None;
}

fn decode_string(data: &pb::Data) -> Option<String> {
    if data.bytes.len() > 0 {
        let mut idata = data.bytes.as_slice();
        let meta = idata.get_u8();
        match meta {
            CORE_DATA_STRING => {
                match from_utf8(idata.chunk()) {
                    Ok(s) => {
                        return Some(s.to_string());
                    }
                    _ => {
                        return None;
                    }
                }
            },
            _ => {
                return None;
            }
        }
    }
    return None;
}

fn decode_key(key: Vec<u8>) -> (u16, Vec<u8>) {
    let mut rdata = key.as_slice();
    let t = rdata.get_u16_le();
    let data = rdata.chunk();
    return (t, data.to_vec());
}

fn decode_address(key: &Vec<u8>) -> Option<String> {
    let mut rdata = key.as_slice();
    let _t = rdata.get_u16_le();
    let data = rdata.chunk();

    let address_hex = hex::encode(data);
    let address_bytes: &mut [u8] = &mut address_hex.as_bytes().to_owned();
    let address_hash = keccak256(&address_hex.as_bytes().to_vec());
    for i in 0..address_bytes.len() {
        let mut hash_byte = address_hash[i/2];
        if i%2 == 0 {
            hash_byte = hash_byte >> 4
        } else {
            hash_byte &= 0xf
        }
        if address_bytes[i] > b'9' && hash_byte > 7 {
            address_bytes[i] -= 32
        }
    }
    let address = match from_utf8(address_bytes) {
        Ok(a) => a,
        _ => {
            return None;
        }
    };

    return Some(String::from("eth.0x".to_owned() + address));
}

fn encode_boolean(b: bool) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_BOOLEAN);
    buf.put_u8(u8::from(b));
    return buf;
}

fn encode_u8(v: u8) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_UINT8);
    buf.put_u8(v);
    return buf;
}

fn encode_i8(v: i8) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_INT8);
    buf.put_i8(v);
    return buf;
}

fn encode_u16(v: u16) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_UINT16);
    buf.put_u16_le(v);
    return buf;
}

fn encode_i16(v: i16) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_INT16);
    buf.put_i16_le(v);
    return buf;
}

fn encode_i32(v: i32) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_INT32);
    buf.put_i32_le(v);
    return buf;
}

fn encode_u32(v: u32) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_UINT32);
    buf.put_u32_le(v);
    return buf;
}

fn encode_i64(v: i64) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_INT64);
    buf.put_i64_le(v);
    return buf;
}

fn encode_u64(v: u64) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_UINT64);
    buf.put_u64_le(v);
    return buf;
}

fn encode_f32(v: f32) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_FLOAT32);
    buf.put_f32_le(v);
    return buf;
}

fn encode_f64(v: f64) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_FLOAT64);
    buf.put_f64_le(v);
    return buf;
}

fn encode_string(v: String) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_STRING);
    buf.put_slice(v.as_bytes());
    return buf;
}

fn encode_bytes(v: &[u8]) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(CORE_DATA_BYTES);
    buf.put_slice(v);
    return buf;
}

fn encode_data(t:u8, v: &[u8]) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u8(t);
    buf.put_slice(v);
    return buf;
}

fn encode_key(t: u16, bytes: Vec<u8>) -> Vec<u8> {
    let mut buf = vec![];
    buf.put_u16_le(t);
    buf.put_slice(&bytes);
    return buf;
}

fn encode<T: ProtoMessage + std::default::Default>(t: u8, m: &T) -> Result<Vec<u8>, Error> {
    let mut buf = vec![t];
    let result = ProtoMessage::encode(m, &mut buf);
    let m = match result {
        Ok(()) => buf.as_slice(),
        Err(err) => {
            return Err(Error::new(ErrorKind::InvalidInput, err));
        },
    };
    return Ok(m.to_vec());
}

fn _contains_key(m: &pb::DataMap, k: &str) -> bool {
    for entry in &m.map {
        if entry.name == k {
            return true;
        }
    }
    return false;
}

fn _get(m: &pb::DataMap, k: &str) -> Option<pb::Data> {
    for entry in &m.map {
        if entry.name == k {
            match &entry.value {
                Some(v) => {
                    return Some(pb::Data{
                        bytes: v.bytes.to_vec(),
                    })
                }
                _ => {
                    return None;
                }
            }
        }
    }
    return None;
}

fn _get_option_string(o: Option<String>) -> String {
    match o {
        Some(s) => {
            return s;
        }
        _ => {
            return "".to_string();
        }
    }
}

fn _get_string(m: &pb::DataMap, k: &str) -> Result<Option<String>, Error> {
    if !_contains_key(m, k) {
        return Ok(None);   
    }
    if let Some(v) = _get(m, k) {
        match decode_string(&v) {
            Some(s) => {
                return Ok(Some(s));
            }
            _ => {
                return Err(Error::new(ErrorKind::InvalidData, "string"));
            }
        }
    }
    return Ok(None);
}

fn _get_i64(m: &pb::DataMap, k: &str) -> Result<Option<i64>, Error> {
    if !_contains_key(m, k) {
        return Ok(None);   
    }
    if let Some(v) = _get(m, k) {
        match decode_i64(&v) {
            Some(s) => {
                return Ok(Some(s));
            }
            _ => {
                return Err(Error::new(ErrorKind::InvalidData, "int64"));
            }
        }
    }
    return Ok(None);
}

fn _get_string_required(m: &pb::DataMap, k: &str) -> Result<String, Error> {
    let r = _get_string(m, k)?;
    match r {
        Some(s) => {
            return Ok(s);
        }
        None => {
            return Err(Error::from(ErrorKind::NotFound));
        }
    }
}

fn _get_i64_required(m: &pb::DataMap, k: &str) -> Result<i64, Error> {
    let r = _get_i64(m, k)?;
    match r {
        Some(v) => {
            return Ok(v);
        }
        None => {
            return Err(Error::from(ErrorKind::NotFound));
        }
    }
}

fn _get_map(m: &pb::DataMap, k: &str) -> Result<Option<pb::DataMap>, Error> {
    if !_contains_key(m, k) {
        return Ok(None);
    }
    if let Some(v) = _get(m, k) {
        match decode::<pb::DataMap>(&v.bytes) {
            Ok(o) => {
                return Ok(o);
            }
            _ => {
                return Err(Error::new(ErrorKind::InvalidData, "data map"));
            }
        }
    }
    return Ok(None);
}

fn _get_list(m: &pb::DataMap, k: &str) -> Result<Option<pb::DataList>, Error> {
    if !_contains_key(m, k) {
        return Ok(None);
    }
    if let Some(v) = _get(m, k) {
        match decode::<pb::DataList>(&v.bytes) {
            Ok(o) => {
                return Ok(o);
            }
            _ => {
                return Err(Error::new(ErrorKind::InvalidData, "data list"));
            }
        }
    }
    return Ok(None);
}

fn _get_map_required(m: &pb::DataMap, k: &str) -> Result<pb::DataMap, Error> {
    let r = _get_map(m, k)?;
    match r {
        Some(sm) => {
            return Ok(sm);
        }
        None => {
            return Err(Error::from(ErrorKind::NotFound));
        }
    }
}

fn _get_list_required(m: &pb::DataMap, k: &str) -> Result<pb::DataList, Error> {
    let r = _get_list(m, k)?;
    match r {
        Some(ll) => {
            return Ok(ll);
        }
        None => {
            return Err(Error::from(ErrorKind::NotFound));
        }
    }
}

fn hash256(bytes: &Vec<u8>) -> Vec<u8> {
    let mut sha256 = Sha256::new();
    sha256.update(bytes);
    return sha256.finalize().to_vec();
}

fn keccak256(bytes: &Vec<u8>) -> Vec<u8> {
    let hash = &mut [0; 32];
    let mut keccak256 = Keccak::v256();
	keccak256.update(bytes);
	keccak256.finalize(hash);
    return hash.to_vec();
}

fn _generate_keypair() -> (SecretKey, PublicKey) {
    let sk = SecretKey::random(&mut OsRng);
    (sk, PublicKey::from_secret_key(&sk))
}

fn _hkdf_sha256(master: &Vec<u8>) -> Result<Vec<u8>, SecpError> {
    let h = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    h.expand(&EMPTY_BYTES, &mut out).map_err(|_| SecpError::InvalidInputLength)?;
    
    Ok(out.to_vec())
}

fn _encapsulate(sk: &SecretKey, peer_pk: &PublicKey) -> Result<Vec<u8>, SecpError> {
    let mut shared_point = *peer_pk;
    shared_point.tweak_mul_assign(sk)?;

    let mut master = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE * 2);
    master.extend(PublicKey::from_secret_key(sk).serialize().iter());
    master.extend(shared_point.serialize().iter());

    _hkdf_sha256(&master.to_vec())
}

fn _decapsulate(pk: &PublicKey, peer_sk: &SecretKey) -> Result<Vec<u8>, SecpError> {
    let mut shared_point = *pk;
    shared_point.tweak_mul_assign(peer_sk)?;

    let mut master = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE * 2);
    master.extend(pk.serialize().iter());
    master.extend(shared_point.serialize().iter());

    _hkdf_sha256(&master.to_vec())
}

fn _generate_aes_key() -> Vec<u8> {
    return Aes256Gcm::generate_key(&mut OsRng).to_vec();
}

fn _generate_aes_nonce() -> Vec<u8> {
    return Aes256Gcm::generate_nonce(&mut OsRng).to_vec();
}

fn _aes_encrypt(k:&Vec<u8>, n:&Vec<u8>, m:&Vec<u8>) -> Result<Vec<u8>, SecpError> {
    let cipher = match Aes256Gcm::new_from_slice(k) {
        Ok(c) => c,
        _ => {
            return Err(SecpError::InvalidInputLength);
        }
    };
    let nonce = Nonce::from_slice(n);
    let ciphertext = match cipher.encrypt(nonce, m.as_ref()) {
        Ok(c) => c,
        _ => {
            return Err(SecpError::InvalidMessage);
        }
    };
    
    Ok(ciphertext)
}

fn _aes_decrypt(k:&Vec<u8>, n:&Vec<u8>, m:&Vec<u8>) -> Result<Vec<u8>, SecpError> {
    let cipher = match Aes256Gcm::new_from_slice(k) {
        Ok(c) => c,
        _ => {
            return Err(SecpError::InvalidInputLength);
        }
    };
    let nonce = Nonce::from_slice(n);
    let dephertext = match cipher.decrypt(nonce, m.as_ref()) {
        Ok(c) => c,
        _ => {
            return Err(SecpError::InvalidMessage);
        }
    };

    Ok(dephertext)
}
 
fn _encrypt(receiver_pk: &PublicKey, msg: &Vec<u8>) -> Result<Vec<u8>, SecpError> {
    let (ephemeral_sk, ephemeral_pk) = _generate_keypair();
    
    let aes_key = _encapsulate(&ephemeral_sk, &receiver_pk)?;
    let nonce = _generate_aes_nonce();
    let encrypted = _aes_encrypt(&aes_key, &nonce, msg)?;

    let mut cipher_text = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE + NONCE_SIZE + encrypted.len());
    cipher_text.extend(ephemeral_pk.serialize().iter());
    cipher_text.extend(nonce);
    cipher_text.extend(encrypted);

    Ok(cipher_text)
}

fn _decrypt(receiver_sk: &SecretKey, msg: &Vec<u8>) -> Result<Vec<u8>, SecpError> {
    if msg.len() < (FULL_PUBLIC_KEY_SIZE + NONCE_SIZE) {
        return Err(SecpError::InvalidMessage);
    }

    let ephemeral_pk = PublicKey::parse_slice(&msg[..FULL_PUBLIC_KEY_SIZE], None)?;
    let nonce = &msg[FULL_PUBLIC_KEY_SIZE..FULL_PUBLIC_KEY_SIZE + NONCE_SIZE];
    let encrypted = &msg[FULL_PUBLIC_KEY_SIZE + NONCE_SIZE..];

    let aes_key = _decapsulate(&ephemeral_pk, &receiver_sk)?;

    _aes_decrypt(&aes_key, &nonce.to_vec(), &encrypted.to_vec())
}