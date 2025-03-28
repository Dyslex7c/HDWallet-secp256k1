use crate::derivation::{ExtendedKey, DerivationPath, DerivationError};
use bitcoin_hashes::{Hash, hash160};
use std::fmt;
use std::error::Error;
use bs58;

pub enum AddressType {
    P2PKH,      // Legacy: 1...
    P2shP2wpkh, // SegWit-compatible: 3...
    P2WPKH,     // Native SegWit: bc1...
}

#[derive(Debug)]
pub enum KeyPairError {
    DerivationError(DerivationError),
    AddressGenerationFailed,
    InvalidSeed,
    SerializationError,
}

impl fmt::Display for KeyPairError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyPairError::DerivationError(e) => write!(f, "Derivation error: {}", e),
            KeyPairError::AddressGenerationFailed => write!(f, "Failed to generate address"),
            KeyPairError::InvalidSeed => write!(f, "Invalid seed"),
            KeyPairError::SerializationError => write!(f, "Failed to serialize extended key"),
        }
    }
}

impl Error for KeyPairError {}

impl From<DerivationError> for KeyPairError {
    fn from(err: DerivationError) -> Self {
        KeyPairError::DerivationError(err)
    }
}

pub struct KeyPair {
    pub extended_key: ExtendedKey,
}

impl KeyPair {
    // Create a new key pair from a seed
    pub fn from_seed(seed: &[u8; 64]) -> Result<Self, KeyPairError> {
        let extended_key = ExtendedKey::from_seed(seed)
            .map_err(|_| KeyPairError::InvalidSeed)?;
            
        Ok(KeyPair { extended_key })
    }
    
    // Derive a child key pair using a string path
    pub fn derive_path(&self, path: &str) -> Result<Self, KeyPairError> {
        let derivation_path = DerivationPath::from_str(path)?;
        let derived_key = derivation_path.derive(&self.extended_key)?;
        
        Ok(KeyPair { extended_key: derived_key })
    }
    
    // Get fingerprint of this key
    pub fn fingerprint(&self) -> [u8; 4] {
        self.extended_key.fingerprint()
    }
    
    // Get the secret key (for display/export)
    pub fn secret_key(&self) -> String {
        // Use proper hex formatting for the private key
        hex::encode(self.extended_key.private_key[..].to_vec())
    }
    
    // Serialize extended private key (xprv)
    pub fn get_xprv(&self) -> Result<String, KeyPairError> {
        // BIP32 serialization format for private key
        let mut data = Vec::with_capacity(78);
        
        // Version bytes for mainnet private key (0x0488ADE4)
        data.extend_from_slice(&[0x04, 0x88, 0xAD, 0xE4]);
        
        // Depth (1 byte)
        data.push(self.extended_key.depth);
        
        // Parent fingerprint (4 bytes)
        data.extend_from_slice(&self.extended_key.parent_fingerprint);
        
        // Child number (4 bytes)
        data.extend_from_slice(&self.extended_key.child_number.to_be_bytes());
        
        // Chain code (32 bytes)
        data.extend_from_slice(&self.extended_key.chain_code);
        
        // 0x00 byte + private key (33 bytes)
        data.push(0x00);
        data.extend_from_slice(&self.extended_key.private_key[..]);
        
        // Convert to Base58Check
        Ok(bs58::encode(&data).with_check().into_string())
    }
    
    // Serialize extended public key (xpub)
    pub fn get_xpub(&self) -> Result<String, KeyPairError> {
        // BIP32 serialization format for public key
        let mut data = Vec::with_capacity(78);
        
        // Version bytes for mainnet public key (0x0488B21E)
        data.extend_from_slice(&[0x04, 0x88, 0xB2, 0x1E]);
        
        // Depth (1 byte)
        data.push(self.extended_key.depth);
        
        // Parent fingerprint (4 bytes)
        data.extend_from_slice(&self.extended_key.parent_fingerprint);
        
        // Child number (4 bytes)
        data.extend_from_slice(&self.extended_key.child_number.to_be_bytes());
        
        // Chain code (32 bytes)
        data.extend_from_slice(&self.extended_key.chain_code);
        
        // Public key (33 bytes) - compressed format
        data.extend_from_slice(&self.extended_key.public_key.serialize());
        
        // Convert to Base58Check
        Ok(bs58::encode(&data).with_check().into_string())
    }
    
    // Get Ethereum address from the key
    pub fn get_eth_address(&self) -> Result<String, KeyPairError> {
        // Get the decompressed public key
        let public_key = self.extended_key.public_key;
        
        // Remove the prefix byte (0x04 for uncompressed keys)
        let key_bytes = public_key.serialize_uncompressed();
        
        let hash = keccak_hash::keccak(&key_bytes[1..]);
    
    // Take the last 20 bytes for the Ethereum address
    let eth_address = &hash.as_bytes()[12..32];
    
    // Return as hex string with "0x" prefix
    Ok(format!("{}", hex::encode(eth_address)))
    }
    
    // Generate a Bitcoin address of the specified type
    pub fn get_address(&self, address_type: AddressType) -> Result<String, KeyPairError> {
        let public_key = &self.extended_key.public_key;
        
        match address_type {
            AddressType::P2PKH => {
                // Legacy address
                // 1. Hash the public key: RIPEMD160(SHA256(pubkey))
                let pubkey_hash = hash160::Hash::hash(&public_key.serialize());
                
                // 2. Add version byte (0x00 for mainnet)
                let mut address_bytes = Vec::with_capacity(21);
                address_bytes.push(0x00);
                address_bytes.extend_from_slice(<hash160::Hash as AsRef<[u8]>>::as_ref(&pubkey_hash));
                
                // 3. Encode with Base58Check
                Ok(bs58::encode(&address_bytes).with_check().into_string())
            },
            
            AddressType::P2shP2wpkh => {
                // SegWit-compatible (P2SH-wrapped)
                // 1. OP_0 + 20-byte pubkey hash
                let pubkey_hash = hash160::Hash::hash(&public_key.serialize());
                
                // 2. Create redeem script: OP_0 + PUSH(20) + <pubkey_hash>
                let mut redeem_script = Vec::with_capacity(22);
                redeem_script.push(0x00); // OP_0
                redeem_script.push(0x14); // PUSH 20 bytes
                redeem_script.extend_from_slice(<hash160::Hash as AsRef<[u8]>>::as_ref(&pubkey_hash));
                
                // 3. Hash the redeem script
                let script_hash = hash160::Hash::hash(&redeem_script);
                
                // 4. Add P2SH version byte (0x05 for mainnet)
                let mut address_bytes = Vec::with_capacity(21);
                address_bytes.push(0x05);
                address_bytes.extend_from_slice(<hash160::Hash as AsRef<[u8]>>::as_ref(&script_hash));
                
                // 5. Encode with Base58Check
                Ok(bs58::encode(&address_bytes).with_check().into_string())
            },
            
            AddressType::P2WPKH => {
                // Native SegWit (bech32)
                let pubkey_hash = hash160::Hash::hash(&public_key.serialize());
                
                // Use bech32 encoding with "bc" prefix (mainnet)
                let program = <hash160::Hash as AsRef<[u8]>>::as_ref(&pubkey_hash).to_vec();
                
                // Encode using bech32
                match bech32::encode("bc", bech32::ToBase32::to_base32(&program), bech32::Variant::Bech32) {
                    Ok(address) => Ok(address),
                    Err(_) => Err(KeyPairError::AddressGenerationFailed),
                }
            }
        }
    }
}