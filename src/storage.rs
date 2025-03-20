use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::error::Error;
use std::fmt;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroize;
use rand::{rngs::OsRng, RngCore}; // Added RngCore trait import here

#[derive(Debug)]
pub enum StorageError {
    IoError(std::io::Error),
    EncryptionError,
    DecryptionError,
    PasswordError,
    InvalidFormat,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorageError::IoError(e) => write!(f, "IO error: {}", e),
            StorageError::EncryptionError => write!(f, "Failed to encrypt data"),
            StorageError::DecryptionError => write!(f, "Failed to decrypt data"),
            StorageError::PasswordError => write!(f, "Invalid password"),
            StorageError::InvalidFormat => write!(f, "Invalid keystore format"),
        }
    }
}

impl Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::IoError(err)
    }
}

pub struct SecureStorage {
    storage_dir: PathBuf,
}

impl SecureStorage {
    pub fn new<P: AsRef<Path>>(storage_dir: P) -> Result<Self, StorageError> {
        let path = storage_dir.as_ref().to_path_buf();
        fs::create_dir_all(&path)?;
        
        Ok(SecureStorage {
            storage_dir: path,
        })
    }
    
    pub fn store_mnemonic(&self, wallet_id: &str, mnemonic: &str, password: &str) -> Result<(), StorageError> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        
        // Generate encryption key from password
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 10_000, &mut key);
        
        // Generate nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the mnemonic
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| StorageError::EncryptionError)?;
        let ciphertext = cipher.encrypt(nonce, mnemonic.as_bytes().as_ref())
            .map_err(|_| StorageError::EncryptionError)?;
        
        // Format for storage: salt + nonce + ciphertext
        let mut data = Vec::with_capacity(salt.len() + nonce_bytes.len() + ciphertext.len());
        data.extend_from_slice(&salt);
        data.extend_from_slice(&nonce_bytes);
        data.extend_from_slice(&ciphertext);
        
        // Write to file
        let file_path = self.get_file_path(wallet_id);
        let mut file = File::create(file_path)?;
        file.write_all(&data)?;
        
        // Clean up sensitive data
        key.zeroize();
        
        Ok(())
    }
    
    pub fn retrieve_mnemonic(&self, wallet_id: &str, password: &str) -> Result<String, StorageError> {
        let file_path = self.get_file_path(wallet_id);
        let mut file = File::open(file_path)?;
        
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        
        if data.len() < 28 { // 16 (salt) + 12 (nonce) + min ciphertext
            return Err(StorageError::InvalidFormat);
        }
        
        // Extract salt, nonce, and ciphertext
        let salt = &data[0..16];
        let nonce_bytes = &data[16..28];
        let ciphertext = &data[28..];
        
        // Generate decryption key from password
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 10_000, &mut key);
        
        // Decrypt the mnemonic
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| StorageError::DecryptionError)?;
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| StorageError::PasswordError)?;
        
        // Clean up sensitive data
        key.zeroize();
        
        // Convert to string
        let mnemonic = String::from_utf8(plaintext)
            .map_err(|_| StorageError::InvalidFormat)?;
        
        Ok(mnemonic)
    }
    
    pub fn exists(&self, wallet_id: &str) -> bool {
        self.get_file_path(wallet_id).exists()
    }
    
    pub fn delete(&self, wallet_id: &str) -> Result<(), StorageError> {
        let file_path = self.get_file_path(wallet_id);
        if file_path.exists() {
            fs::remove_file(file_path)?;
        }
        Ok(())
    }
    
    fn get_file_path(&self, wallet_id: &str) -> PathBuf {
        self.storage_dir.join(format!("{}.key", wallet_id))
    }
}