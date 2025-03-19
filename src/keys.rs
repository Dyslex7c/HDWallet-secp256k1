use secp256k1::{Secp256k1, SecretKey, PublicKey};
use bitcoin_hashes::{Hash, hash160};
use std::fmt;

use crate::derivation::{ExtendedKey, DerivationError};

#[derive(Debug)]
pub enum KeyError {
    InvalidKey,
    SerializationError,
    DerivationError(DerivationError),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyError::InvalidKey => write!(f, "Invalid key"),
            KeyError::SerializationError => write!(f, "Key serialization error"),
            KeyError::DerivationError(e) => write!(f, "Derivation error: {}", e),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<DerivationError> for KeyError {
    fn from(err: DerivationError) -> Self {
        KeyError::DerivationError(err)
    }
}

#[derive(Clone)]
pub struct KeyPair {
    pub extended_key: ExtendedKey,
    secp: Secp256k1<secp256k1::All>,
}

impl KeyPair {
    pub fn from_seed(seed: &[u8]) -> Result<Self, KeyError> {
        let secp = Secp256k1::new();
        let extended_key = ExtendedKey::from_seed(seed)
            .map_err(KeyError::DerivationError)?;
        
        Ok(KeyPair {
            extended_key,
            secp,
        })
    }
    
    pub fn derive_child(&self, index: u32) -> Result<Self, KeyError> {
        let child_key = self.extended_key.derive_child(index)?;
        
        Ok(KeyPair {
            extended_key: child_key,
            secp: self.secp.clone(),
        })
    }
    
    pub fn derive_path(&self, path: &str) -> Result<Self, KeyError> {
        use crate::derivation::DerivationPath;
        
        let path = DerivationPath::from_str(path)?;
        let derived_key = path.derive(&self.extended_key)?;
        
        Ok(KeyPair {
            extended_key: derived_key,
            secp: self.secp.clone(),
        })
    }
    
    pub fn secret_key(&self) -> &SecretKey {
        &self.extended_key.private_key
    }
    
    pub fn public_key(&self) -> &PublicKey {
        &self.extended_key.public_key
    }
    
    pub fn to_wif(&self) -> Result<String, KeyError> {
        // Simple WIF implementation for Bitcoin mainnet
        let mut bytes = vec![0x80]; // mainnet private key prefix
        bytes.extend_from_slice(&self.extended_key.private_key[..]);
        bytes.push(0x01); // compression flag
        
        let checksum = bitcoin_hashes::sha256d::Hash::hash(&bytes);
        bytes.extend_from_slice(&checksum[0..4]);
        
        Ok(bs58::encode(bytes).into_string())
    }
    
    pub fn get_address(&self, address_type: AddressType) -> Result<String, KeyError> {
        match address_type {
            AddressType::P2PKH => self.get_p2pkh_address(),
            AddressType::P2SH_P2WPKH => self.get_p2sh_p2wpkh_address(),
            AddressType::P2WPKH => self.get_p2wpkh_address(),
        }
    }
    
    fn get_p2pkh_address(&self) -> Result<String, KeyError> {
        let pub_key = self.extended_key.public_key.serialize();
        let hash = hash160::Hash::hash(&pub_key);
        
        // Bitcoin mainnet P2PKH address (prefix 0x00)
        let mut address_bytes = vec![0x00];
        address_bytes.extend_from_slice(&hash[..]);
        
        let checksum = bitcoin_hashes::sha256d::Hash::hash(&address_bytes);
        address_bytes.extend_from_slice(&checksum[0..4]);
        
        Ok(bs58::encode(address_bytes).into_string())
    }
    
    fn get_p2sh_p2wpkh_address(&self) -> Result<String, KeyError> {
        let pub_key = self.extended_key.public_key.serialize();
        let hash = hash160::Hash::hash(&pub_key);
        
        // Create P2WPKH redeem script
        let mut redeem_script = vec![0x00, 0x14]; // OP_0 + push 20 bytes
        redeem_script.extend_from_slice(&hash[..]);
        
        // Hash the redeem script
        let script_hash = hash160::Hash::hash(&redeem_script);
        
        // Bitcoin mainnet P2SH address (prefix 0x05)
        let mut address_bytes = vec![0x05];
        address_bytes.extend_from_slice(&script_hash[..]);
        
        let checksum = bitcoin_hashes::sha256d::Hash::hash(&address_bytes);
        address_bytes.extend_from_slice(&checksum[0..4]);
        
        Ok(bs58::encode(address_bytes).into_string())
    }
    
    fn get_p2wpkh_address(&self) -> Result<String, KeyError> {
        let pub_key = self.extended_key.public_key.serialize();
        let hash = hash160::Hash::hash(&pub_key);
        
        // Bitcoin mainnet Bech32 address (prefix "bc")
        // Note: This is a simplified implementation; a real implementation would use a proper bech32 library
        let mut program = vec![0x00]; // Version 0
        program.extend_from_slice(&hash[..]);
        
        match bech32::encode("bc", program.to_base32(), bech32::Variant::Bech32) {
            Ok(address) => Ok(address),
            Err(_) => Err(KeyError::SerializationError),
        }
    }
    
    pub fn fingerprint(&self) -> [u8; 4] {
        self.extended_key.fingerprint()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AddressType {
    P2PKH,      // Legacy
    P2SH_P2WPKH, // SegWit-compatible
    P2WPKH,     // Native SegWit
}

// Helper trait for bech32 encoding
trait ToBase32 {
    fn to_base32(&self) -> Vec<bech32::u5>;
}

impl ToBase32 for Vec<u8> {
    fn to_base32(&self) -> Vec<bech32::u5> {
        let mut result = Vec::with_capacity(self.len() * 8 / 5 + 1);
        for chunk in self.chunks(5) {
            let mut buffer = 0u64;
            let mut bits = 0;
            
            for &byte in chunk {
                buffer |= (byte as u64) << bits;
                bits += 8;
            }
            
            while bits >= 5 {
                result.push(bech32::u5::try_from_u8((buffer & 0x1F) as u8).unwrap());
                buffer >>= 5;
                bits -= 5;
            }
            
            if bits > 0 {
                result.push(bech32::u5::try_from_u8((buffer & 0x1F) as u8).unwrap());
            }
        }
        
        result
    }
}