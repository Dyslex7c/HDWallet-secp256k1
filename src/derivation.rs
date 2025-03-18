use hmac::{Hmac, Mac};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::Sha512;
use std::fmt;
use bitcoin_hashes::{Hash, hash160};

const HARDENED_BIT: u32 = 0x80000000;

#[derive(Debug)]
pub enum DerivationError {
    InvalidPath,
    InvalidChildNumber,
    InvalidParentKey,
    KeyDerivationFailed,
    HmacError,
    Secp256k1Error,
}

impl fmt::Display for DerivationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DerivationError::InvalidPath => write!(f, "Invalid derivation path"),
            DerivationError::InvalidChildNumber => write!(f, "Invalid child number"),
            DerivationError::InvalidParentKey => write!(f, "Invalid parent key"),
            DerivationError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            DerivationError::HmacError => write!(f, "HMAC operation failed"),
            DerivationError::Secp256k1Error => write!(f, "Secp256k1 operation failed"),
        }
    }
}

impl std::error::Error for DerivationError {}

/// Represents a BIP32 extended key, containing both private and public components
#[derive(Clone)]
pub struct ExtendedKey {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    pub chain_code: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
}

impl ExtendedKey {
    /// Creates a new master key from a seed
    pub fn from_seed(seed: &[u8]) -> Result<Self, DerivationError> {
        let secp = Secp256k1::new();
        
        // HMAC-SHA512 with key "Bitcoin seed"
        let mut hmac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed")
            .map_err(|_| DerivationError::HmacError)?;
        
        hmac.update(seed);
        let result = hmac.finalize().into_bytes();
        
        // Split the result into left and right halves
        let mut left = [0u8; 32];
        let mut chain_code = [0u8; 32];
        left.copy_from_slice(&result[0..32]);
        chain_code.copy_from_slice(&result[32..64]);
        
        // Create the master key
        let private_key = SecretKey::from_slice(&left)
            .map_err(|_| DerivationError::Secp256k1Error)?;
        
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        
        Ok(ExtendedKey {
            private_key,
            public_key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: 0,
        })
    }
    
    /// Derives a child key based on the provided index
    pub fn derive_child(&self, index: u32) -> Result<Self, DerivationError> {
        let secp = Secp256k1::new();
        
        // Prepare the data for HMAC
        let mut data = Vec::with_capacity(37); // 33 bytes for public key + 4 bytes for index
        
        if index & HARDENED_BIT != 0 {
            // Hardened derivation
            data.push(0);
            data.extend_from_slice(&self.private_key[..]);
        } else {
            // Normal derivation
            data.extend_from_slice(&self.public_key.serialize());
        }
        
        // Append the index in big-endian
        data.extend_from_slice(&index.to_be_bytes());
        
        // HMAC-SHA512
        let mut hmac = Hmac::<Sha512>::new_from_slice(&self.chain_code)
            .map_err(|_| DerivationError::HmacError)?;
        
        hmac.update(&data);
        let result = hmac.finalize().into_bytes();
        
        // Split the result into left and right halves
        let mut left = [0u8; 32];
        let mut chain_code = [0u8; 32];
        left.copy_from_slice(&result[0..32]);
        chain_code.copy_from_slice(&result[32..64]);
        
        // Calculate the child private key
        let tweak = SecretKey::from_slice(&left)
            .map_err(|_| DerivationError::Secp256k1Error)?;
            
            let child_private_key = {
                // Clone the parent key and add the tweak to it
                let child = self.private_key.clone();
                let scalar = tweak.into();
                child.add_tweak(&scalar)
                    .map_err(|_| DerivationError::KeyDerivationFailed)?;
                child
            };
        
        let child_public_key = PublicKey::from_secret_key(&secp, &child_private_key);
        
        // Calculate parent fingerprint
        let parent_fingerprint = self.fingerprint();
        
        Ok(ExtendedKey {
            private_key: child_private_key,
            public_key: child_public_key,
            chain_code,
            depth: self.depth + 1,
            parent_fingerprint,
            child_number: index,
        })
    }
    
    /// Calculates the fingerprint of this key
    pub fn fingerprint(&self) -> [u8; 4] {
        let mut result = [0u8; 4];
        let serialized_pubkey = self.public_key.serialize();
        let hash = hash160::Hash::hash(&serialized_pubkey);
        result.copy_from_slice(&hash[0..4]);
        result
    }
    
    /// Gets the extended public key (removing private key information)
    pub fn neuter(&self) -> PublicKey {
        self.public_key
    }
}

/// Represents a BIP32 derivation path
#[derive(Debug, Clone)]
pub struct DerivationPath {
    indices: Vec<u32>,
}

impl DerivationPath {
    /// Creates a new derivation path from a string
    pub fn from_str(path: &str) -> Result<Self, DerivationError> {
        if !path.starts_with('m') {
            return Err(DerivationError::InvalidPath);
        }
        
        let indices: Result<Vec<u32>, _> = path
            .split('/')
            .skip(1) // Skip the leading 'm'
            .filter(|s| !s.is_empty())
            .map(|component| {
                let hardened = component.ends_with('\'') || component.ends_with('h');
                let index_str = if hardened {
                    &component[..component.len() - 1]
                } else {
                    component
                };
                
                match index_str.parse::<u32>() {
                    Ok(index) => {
                        if hardened {
                            Ok(index | HARDENED_BIT)
                        } else {
                            Ok(index)
                        }
                    },
                    Err(_) => Err(DerivationError::InvalidChildNumber),
                }
            })
            .collect();
        
        indices.map(|indices| DerivationPath { indices })
    }
    
    /// Derives a key following this path
    pub fn derive(&self, root: &ExtendedKey) -> Result<ExtendedKey, DerivationError> {
        let mut key = root.clone();
        
        for &index in &self.indices {
            key = key.derive_child(index)?;
        }
        
        Ok(key)
    }
}

/// Utility functions for common derivation paths
pub mod paths {
    use super::DerivationPath;
    
    /// BIP44 - Multi-Account Hierarchy for Deterministic Wallets
    /// Format: m/44'/coin_type'/account'/change/address_index
    pub fn bip44(coin_type: u32, account: u32, change: bool, address_index: u32) -> DerivationPath {
        let path = format!("m/44'/{}'/{}'/{}/{}", 
            coin_type, 
            account, 
            if change { 1 } else { 0 }, 
            address_index
        );
        DerivationPath::from_str(&path).unwrap()
    }
    
    /// BIP49 - Derivation scheme for P2WPKH-nested-in-P2SH
    /// Format: m/49'/coin_type'/account'/change/address_index
    pub fn bip49(coin_type: u32, account: u32, change: bool, address_index: u32) -> DerivationPath {
        let path = format!("m/49'/{}'/{}'/{}/{}", 
            coin_type, 
            account, 
            if change { 1 } else { 0 }, 
            address_index
        );
        DerivationPath::from_str(&path).unwrap()
    }
    
    /// BIP84 - Derivation scheme for P2WPKH
    /// Format: m/84'/coin_type'/account'/change/address_index
    pub fn bip84(coin_type: u32, account: u32, change: bool, address_index: u32) -> DerivationPath {
        let path = format!("m/84'/{}'/{}'/{}/{}", 
            coin_type, 
            account, 
            if change { 1 } else { 0 }, 
            address_index
        );
        DerivationPath::from_str(&path).unwrap()
    }
    
    /// Bitcoin - Coin type 0
    pub const BITCOIN: u32 = 0;
    
    /// Ethereum - Coin type 60
    pub const ETHEREUM: u32 = 60;
}