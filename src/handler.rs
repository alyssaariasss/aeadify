use std::{fs::DirBuilder, path::Path};

use base64::prelude::*;
use orion::{
    aead::{open, seal},
    kdf::{derive_key, Password, Salt},
    kex::SecretKey,
};

/// Model to hold generated SecretKey and Salt for passphrase.
#[derive(Debug)]
struct KeySalt {
    key: SecretKey,
    salt: Salt,
}

/// Derives a password using the decoded passphrase and internally adds a default salt.
///
/// It then derives the SecretKey from the passphrase and the generated salt using a password-hashing function Argon2i.
///
/// # Parameters
///
/// `passphrase` - String that serves as the user's password.
///
/// # Returns
///
/// Returns the generated SecretKey and salt represented by the `KeySalt` struct.
fn derive_key_with_random_salt(passphrase: &String) -> KeySalt {
    let user_password = Password::from_slice(passphrase.as_bytes()).unwrap();
    let salt = Salt::default();

    let key = derive_key(&user_password, &salt, 3, 1 << 16, 32).unwrap();
    KeySalt { key, salt }
}

/// Derives a password using the decoded passphrase and externally added salt (from slice of encrypted string).
///
/// It then derives the SecretKey from the passphrase and the generated salt using a password-hashing function Argon2i.
///
/// # Parameters
///
/// `passphrase` - String that serves as the user's password.
/// `salt` - Randomly generated salt.
///
/// # Returns
///
/// Returns the stretched passphrase with salt as a `SecretKey`.
fn derive_key_with_custom_salt(passphrase: &String, salt: &[u8]) -> SecretKey {
    let salt = Salt::from_slice(salt).unwrap();
    let user_password = Password::from_slice(passphrase.as_bytes()).unwrap();
    derive_key(&user_password, &salt, 3, 1 << 16, 32).unwrap()
}

/// Encrypts the given string bytes using password.
///
/// # Parameters
///
/// `string_as_bytes` - Content to be encrypted that is converted into bytes.
///
/// `password` - String that serves as the user's password.
///
/// # Returns
///
/// Returns the encrypted string as base64.
fn enrypt_string(
    string_as_bytes: &[u8],
    password: &String,
) -> Result<String, Box<dyn std::error::Error>> {
    let passphrase = derive_key_with_random_salt(password);
    let ciphertext = seal(&passphrase.key, string_as_bytes)?;
    let cipertext_with_salt = [passphrase.salt.as_ref(), &ciphertext].concat();
    encode_to_base64(&cipertext_with_salt)
}

/// Encodes bytes as base64 string.
///
/// # Parameters
///
/// `encrypted_bytes` - Encrypted content that is converted into bytes.
///
/// # Returns
///
/// Returns the base64 String of `encrypted_bytes`.
fn encode_to_base64(encrypted_bytes: &Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
    Ok(BASE64_STANDARD.encode(encrypted_bytes))
}

/// Decodes base64 string as bytes.
///
/// # Parameters
///
/// `encoded_base64` - Encoded base64 content of the encrypted string.
///
/// # Returns
///
/// Returns the resulting bytes of `encoded_base64`.
fn decode_base64(encoded_base64: &String) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(BASE64_STANDARD.decode(encoded_base64)?)
}

/// Decrypts a base64 string using password and returns it as a String.
///
/// # Parameters
///
/// `encoded_base64` - Encoded base64 content of the encrypted string.
///
/// `password` - String that serves as the user's password.
///
/// # Returns
///
/// Returns the decrypted cipherstring of `encoded_base64`.
fn decrypt_cipherstring(
    encoded_base64: &String,
    password: &String,
) -> Result<String, Box<dyn std::error::Error>> {
    let cipherstring = decode_base64(encoded_base64)?;
    let (salt, cipherstring) = cipherstring.split_at(16);
    let passphrase = derive_key_with_custom_salt(password, salt);
    let decrypted_text = open(&passphrase, cipherstring)?;
    Ok(String::from_utf8(decrypted_text)?)
}

/// Stores encrypted content in the `encrypted` directory.
///
/// # Parameters
///
/// `key` - Borrowed reference to the key name.
///
/// `content` - Content to be encrypted.
///
/// `password` - User-input password
pub fn store_keys(
    key: &String,
    content: &String,
    password: &String,
) -> Result<(), Box<dyn std::error::Error>> {
    let dir_path = Path::new("./encrypted");
    let tree = sled::open(dir_path)?;

    if !dir_path.exists() {
        DirBuilder::new().recursive(true).create(dir_path)?;
    }

    let string_bytes = content.as_bytes().to_vec();
    let encrypted_content = enrypt_string(&string_bytes, password)?;
    let value = bincode::serialize(&encrypted_content)?;
    tree.insert(key, value)?;

    Ok(())
}

/// Returns decrypted content from the `encrypted` directory.
///
/// # Parameters
///
/// `key` - Borrowed reference to the key name.
///
/// `password` - User-input password
///
/// # Returns
///
/// Returns the retrieved and decrypted content into String.
pub fn get_keys(key: &String, password: &String) -> Result<String, Box<dyn std::error::Error>> {
    let dir_path = Path::new("./encrypted");
    let tree = sled::open(dir_path)?;

    if let Some(value) = tree.get(key)? {
        let raw_value: String = bincode::deserialize(&value)?;
        let value = decrypt_cipherstring(&raw_value, password)?;
        Ok(value)
    } else {
        Err("Key not found".into())
    }
}
