use bip39::Mnemonic;
use rand::{rngs::OsRng, RngCore};
use std::fmt;
use std::error::Error as StdError;

pub enum MnemonicStrength {
    Words12,
    Words15,
    Words18,
    Words21,
    Words24,
}

impl MnemonicStrength {
    fn to_entropy_bits(&self) -> usize {
        match self {
            MnemonicStrength::Words12 => 128,
            MnemonicStrength::Words15 => 160,
            MnemonicStrength::Words18 => 192,
            MnemonicStrength::Words21 => 224,
            MnemonicStrength::Words24 => 256,
        }
    }
}

#[derive(Debug)]
pub enum MnemonicError {
    InvalidMnemonic,
    EntropyGenerationFailed,
    //SeedGenerationFailed,
}

impl fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MnemonicError::InvalidMnemonic => write!(f, "Invalid mnemonic phrase"),
            MnemonicError::EntropyGenerationFailed => write!(f, "Failed to generate entropy"),
        }
    }
}

impl StdError for MnemonicError {}

pub struct SecureMnemonic {
    mnemonic: Mnemonic,
}

impl SecureMnemonic {
    pub fn generate(strength: MnemonicStrength) -> Result<Self, MnemonicError> {
        let entropy_bits = strength.to_entropy_bits();
        let entropy_bytes = entropy_bits / 8;
        
        let entropy = generate_entropy(entropy_bytes)
            .map_err(|_| MnemonicError::EntropyGenerationFailed)?;
        
        match Mnemonic::from_entropy(&entropy) {
            Ok(mnemonic) => Ok(Self { mnemonic }),
            Err(_) => Err(MnemonicError::EntropyGenerationFailed),
        }
    }
    
    pub fn from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        match Mnemonic::parse_normalized(phrase) {
            Ok(mnemonic) => Ok(Self { mnemonic }),
            Err(_) => Err(MnemonicError::InvalidMnemonic),
        }
    }
    
    pub fn phrase(&self) -> String {
        let mut result = String::new();
        for (i, word) in self.mnemonic.word_iter().enumerate() {
            if i > 0 {
                result.push(' ');
            }
            result.push_str(word);
        }
        result
    }
    
    pub fn to_seed(&self, passphrase: &str) -> Result<[u8; 64], MnemonicError> {
        let seed_bytes = self.mnemonic.to_seed(passphrase);
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&seed_bytes[..64]);
        Ok(seed)
    }
}

impl Drop for SecureMnemonic {
    fn drop(&mut self) {}
}

pub fn generate_entropy(byte_length: usize) -> Result<Vec<u8>, MnemonicError> {
    let mut bytes = vec![0u8; byte_length];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}