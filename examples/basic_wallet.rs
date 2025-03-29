use key_vault::KeyPair;
use key_vault::{
    KeyVault, MnemonicStrength, AddressType,
};
use std::io::{self, Write, Read};
use std::path::Path;
use std::fs;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("KeyVault HD Wallet Demo");
    println!("======================");
    
    let storage_dir = Path::new("./wallet-data");
    let vault = KeyVault::new(storage_dir)?;

    let config_path = storage_dir.join("wallet_config.txt");
    let wallet_id = if config_path.exists() {
        let mut config_file = fs::File::open(&config_path)?;
        let mut wallet_id = String::new();
        config_file.read_to_string(&mut wallet_id)?;
        wallet_id.trim().to_string()
    } else {
        let wallet_id: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        
        let mut config_file = fs::File::create(&config_path)?;
        config_file.write_all(wallet_id.as_bytes())?;
        wallet_id
    };
    
    let wallet_password = prompt_password("Enter your wallet password: ")?;
    
    let mnemonic = if std::path::Path::new("./wallet-data").join(format!("{}.key", wallet_id)).exists() {
        println!("Loading existing wallet '{}'...", wallet_id);
        vault.load_wallet(&wallet_id, &wallet_password)?
    } else {
        println!("Creating new wallet '{}'...", wallet_id);
        let mnemonic = vault.create_wallet(&wallet_id, MnemonicStrength::Words12, &wallet_password)?;
        
        println!("\n⚠️  IMPORTANT: Write down your mnemonic phrase and store it securely!");
        println!("Mnemonic: {}\n", mnemonic.phrase());
        print!("Press Enter to continue...");
        io::stdout().flush()?;
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer)?;
        
        mnemonic
    };
    
    let passphrase = ""; // Optional BIP39 passphrase
    let master_keypair = vault.create_keypair(&mnemonic, passphrase)?;
    
    println!("Master key fingerprint: {:02x?}", master_keypair.fingerprint());
    
    println!("\nMaster Extended Keys:");
    let master_xprv = master_keypair.get_xprv()?;
    let master_xpub = master_keypair.get_xpub()?;
    println!("XPRV: {}", master_xprv);
    println!("XPUB: {}", master_xpub);
    
    println!("\nDerived Addresses and Extended Keys:");
    
    let bip44_path = "m/44'/0'/0'/0/0";
    let bip44_keypair = KeyPair::from_seed(&mnemonic.to_seed(passphrase)?)?
        .derive_path(bip44_path)?;
    let legacy_address = bip44_keypair.get_address(AddressType::P2PKH)?;
    let bip44_xprv = bip44_keypair.get_xprv()?;
    let bip44_xpub = bip44_keypair.get_xpub()?;
    
    println!("\nBIP44 - Legacy Address (P2PKH)");
    println!("Path:      {}", bip44_path);
    println!("Address:   {}", legacy_address);
    println!("XPRV:      {}", bip44_xprv);
    println!("XPUB:      {}", bip44_xpub);
    println!("Priv Key:  {}", bip44_keypair.secret_key());
    
    let bip49_path = "m/49'/0'/0'/0/0";
    let bip49_keypair = KeyPair::from_seed(&mnemonic.to_seed(passphrase)?)?
        .derive_path(bip49_path)?;
    let segwit_compat_address = bip49_keypair.get_address(AddressType::P2shP2wpkh)?;
    let bip49_xprv = bip49_keypair.get_xprv()?;
    let bip49_xpub = bip49_keypair.get_xpub()?;
    
    println!("\nBIP49 - SegWit-compatible Address (P2SH-P2WPKH)");
    println!("Path:      {}", bip49_path);
    println!("Address:   {}", segwit_compat_address);
    println!("XPRV:      {}", bip49_xprv);
    println!("XPUB:      {}", bip49_xpub);
    println!("Priv Key:  {}", bip49_keypair.secret_key());
    
    let bip84_path = "m/84'/0'/0'/0/0";
    let bip84_keypair = KeyPair::from_seed(&mnemonic.to_seed(passphrase)?)?
        .derive_path(bip84_path)?;
    let native_segwit_address = bip84_keypair.get_address(AddressType::P2WPKH)?;
    let bip84_xprv = bip84_keypair.get_xprv()?;
    let bip84_xpub = bip84_keypair.get_xpub()?;
    
    println!("\nBIP84 - Native SegWit Address (P2WPKH)");
    println!("Path:      {}", bip84_path);
    println!("Address:   {}", native_segwit_address);
    println!("XPRV:      {}", bip84_xprv);
    println!("XPUB:      {}", bip84_xpub);
    println!("Priv Key:  {}", bip84_keypair.secret_key());
    
    let eth_path = "m/44'/60'/0'/0/0";
    let eth_keypair = KeyPair::from_seed(&mnemonic.to_seed(passphrase)?)?
        .derive_path(eth_path)?;
    let eth_xprv = eth_keypair.get_xprv()?;
    let eth_xpub = eth_keypair.get_xpub()?;
    
    println!("\nEthereum Account");
    println!("Path:        {}", eth_path);
    println!("Private Key: {}", eth_keypair.secret_key());
    println!("XPRV:        {}", eth_xprv);
    println!("XPUB:        {}", eth_xpub);
    println!("ETH Address: 0x{}", eth_keypair.get_eth_address()?);
    
    println!("\nWallet operations completed successfully!");
    Ok(())
}

fn prompt_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    #[cfg(not(windows))]
    {
        use rpassword::read_password;
        print!("{}", prompt);
        io::stdout().flush()?;
        let password = read_password()?;
        Ok(password)
    }
}