//! This library implements BIP32/39/44 for creating and managing hierarchical deterministic wallets.
//! It supports seed generation from mnemonic phrases, key derivation, and secure storage.

pub mod mnemonic;
pub mod derivation;
pub mod keys;
pub mod storage;

// Re-export key types for convenience
pub use mnemonic::{
    MnemonicStrength,
    MnemonicError,
    SecureMnemonic,
    generate_entropy,
};

pub use derivation::{
    ExtendedKey,
    DerivationPath,
    DerivationError,
    paths,
};

pub use keys::{
    KeyPair,
    KeyPairError,
    AddressType,
};

pub use storage::{
    SecureStorage,
    StorageError,
};

/// KeyVault API for creating and managing wallets
pub struct KeyVault {
    storage: SecureStorage,
}

impl KeyVault {
    /// Creates a new KeyVault instance with the specified storage directory
    pub fn new<P: AsRef<std::path::Path>>(storage_dir: P) -> Result<Self, storage::StorageError> {
        let storage = SecureStorage::new(storage_dir)?;
        Ok(KeyVault { storage })
    }
    
    /// Creates a new wallet with a randomly generated mnemonic phrase
    pub fn create_wallet(
        &self,
        wallet_id: &str,
        strength: MnemonicStrength,
        password: &str,
    ) -> Result<SecureMnemonic, Box<dyn std::error::Error>> {
        // Check if wallet already exists
        if self.storage.exists(wallet_id) {
            return Err(format!("Wallet '{}' already exists", wallet_id).into());
        }
        
        // Generate new mnemonic
        let mnemonic = SecureMnemonic::generate(strength)?;
        
        // Store encrypted mnemonic
        self.storage.store_mnemonic(wallet_id, &mnemonic.phrase(), password)?;
        
        Ok(mnemonic)
    }
    
    /// Imports an existing wallet from a mnemonic phrase
    pub fn import_wallet(
        &self,
        wallet_id: &str,
        phrase: &str,
        password: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Check if wallet already exists
        if self.storage.exists(wallet_id) {
            return Err(format!("Wallet '{}' already exists", wallet_id).into());
        }
        
        // Validate mnemonic phrase
        let mnemonic = SecureMnemonic::from_phrase(phrase)?;
        
        // Store encrypted mnemonic
        self.storage.store_mnemonic(wallet_id, &mnemonic.phrase(), password)?;
        
        Ok(())
    }
    
    /// Loads a wallet from storage
    pub fn load_wallet(
        &self,
        wallet_id: &str,
        password: &str,
    ) -> Result<SecureMnemonic, Box<dyn std::error::Error>> {
        // Check if wallet exists
        if !self.storage.exists(wallet_id) {
            return Err(format!("Wallet '{}' does not exist", wallet_id).into());
        }
        
        // Retrieve and decrypt mnemonic
        let phrase = self.storage.retrieve_mnemonic(wallet_id, password)?;
        let mnemonic = SecureMnemonic::from_phrase(&phrase)?;
        
        Ok(mnemonic)
    }
    
    /// Deletes a wallet from storage
    pub fn delete_wallet(&self, wallet_id: &str) -> Result<(), storage::StorageError> {
        self.storage.delete(wallet_id)
    }
    
    /// Creates a keypair from a mnemonic with an optional passphrase
    pub fn create_keypair(
        &self,
        mnemonic: &SecureMnemonic,
        passphrase: &str,
    ) -> Result<KeyPair, Box<dyn std::error::Error>> {
        let seed = mnemonic.to_seed(passphrase)?;
        let keypair = KeyPair::from_seed(&seed)?;
        
        Ok(keypair)
    }
}