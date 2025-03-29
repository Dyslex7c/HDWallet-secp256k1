# HDWallet-secp256k1

A comprehensive implementation of hierarchical deterministic (HD) wallet specifications for cryptographic key management in blockchain systems, following BIP32, BIP39, BIP43, and BIP44 standards.

## Technical Overview

This provides a robust framework for deterministic key generation and management based on industry-standard Bitcoin Improvement Proposals (BIPs). The library implements the complete HD wallet specification stack:

- **BIP32**: Hierarchical Deterministic Wallets
- **BIP39**: Mnemonic code for generating deterministic keys
- **BIP43**: Purpose field for deterministic wallets
- **BIP44**: Multi-account hierarchy for deterministic wallets
- **BIP49**: Derivation scheme for P2WPKH-nested-in-P2SH addresses
- **BIP84**: Derivation scheme for Native SegWit (P2WPKH) addresses

![alt text](hdwallet.png)

## Sample Wallet Construction

```
Enter your wallet password: 
Creating new wallet 'sTzPr3tUke7l5kNM'...

⚠️  IMPORTANT: Write down your mnemonic phrase and store it securely!
Mnemonic: future horse antique dragon park circle fragile dove youth race throw follow

Press Enter to continue...
Master key fingerprint: [75, b6, 0d, fb]

Master Extended Keys:
XPRV: xprv9s21ZrQH143K2fG5PWNe8P3GZuTeevgY4vtEyphfzM8Ef1TrTEtbWNKpyoWE8hgzZuxtFvukyo1tEyU9JvK1ChoNkBwNT1sppNnq15zPJaB
XPUB: xpub661MyMwAqRbcF9LYVXueVWz17wJ94PQPS9oqnD7HYgfDXonzznCr4AeJq4PXmM2tFKTWw5ifwhG2Po6GFnftooKH5vhrVjgymXkPW58X8Zc

Derived Addresses and Extended Keys:

BIP44 - Legacy Address (P2PKH)
Path:      m/44'/0'/0'/0/0
Address:   1BjQ9pdziv2DABXX7nntVodYTkAPEBAnbm
XPRV:      xprvA3HsPLpM8G2yFcG95G9MXfahSPSmTYTxm11dPrwrvnMDb8axs8vQaB9KYJQn9Vo72cfyEcUSrwqdAgMssDrgLuDGVFH7dqp8YN5VjyHfytU
XPUB:      xpub6GHDnrMExdbGU6LcBHgMtoXRzRHFs1Bp8DwECFMUV7tCTvv7QgEf7yToPZJ5n98zi2AbumHMpr5mKVyzp6DZwzjApz3bgZdHVX34EwdCD9z
Priv Key:  2e87ea76787235eb5c1c13a20f67cd6da2bce42f2f6e03020b9fa5eeefbe6b99

BIP49 - SegWit-compatible Address (P2SH-P2WPKH)
Path:      m/49'/0'/0'/0/0
Address:   37uRpMaJosaisXEHrdMnNjZxbrHZxagS5a
XPRV:      xprvA3HsPLpM8G2yFLb4xMDhgujBN9KLVGCySSFqiPzbr8YUrfBnsBSpLqGFxNRCd5Er8tfpAzYp4vXxBJtDuEUZorYuv1Yg3y9Dm8rURiMQ4iu
XPUB:      xpub6GHDnrMExdbGTpfY4Nki43fuvB9ptivpofBSWnQDQU5TjTWwQim4tdajodJWFiajpJASr9Mj2pn6L8WLr6qTQx4pFkKA6gxNiHp2vdvGXmj
Priv Key:  2e87ea76787235eb5c1c13a20f67cd6da2bce42f2f6e03020b9fa5eeefbe6b99

BIP84 - Native SegWit Address (P2WPKH)
Path:      m/84'/0'/0'/0/0
Address:   bc1wkmqm7l657jze6urmzwtpxlusq6fz85mlaamqg
XPRV:      xprvA3HsPLpM8G2yGLfjysBKraegrqxuGa6xeYDihgsFsE3mnqkckHcpYKKoypfJr1gXqZWvU9pwWGHPcNnDDKARt6UowWaYkDEx2UH55f18h4v
XPUB:      xpub6GHDnrMExdbGUpkD5tiLDibRQsoPg2pp1m9KW5GsRZakfe5mHpw567eHq5YcUf2RWy1Z9JdrUAXXmCQLABXKVBziHFM2nw46ydEdaYUhb5L
Priv Key:  2e87ea76787235eb5c1c13a20f67cd6da2bce42f2f6e03020b9fa5eeefbe6b99

Ethereum Account
Path:        m/44'/60'/0'/0/0
Private Key: 2e87ea76787235eb5c1c13a20f67cd6da2bce42f2f6e03020b9fa5eeefbe6b99
XPRV:        xprvA3HsPLpM8G2yFyanUxAg3Nw5DnkQGakMUY1BxRVprSxwtQXygaQVQ7Ki3GN8YRWwCD2u2M1ApHRbBLQkhcdCvonU4FAx8oranCSD816mpKh
XPUB:        xpub6GHDnrMExdbGUTfFayhgQWsompatg3UCqkvnkouSQnVvmCs8E7ijwueBtXFSB4rpscXXhVp5nBfjLA2seUz6XuJNPywSBXfjjMPmczvrzPh
ETH Address: 0xdc8a30bf53313dea8a2b0a8f4b00c7f4809b166d
```

## Cryptographic Foundations

### Key Derivation Mechanism

HDWallet-secp256k1 implements the complete BIP32 key derivation protocol:

- Extended private keys (xprv): 512 bits consisting of a 256-bit private key and a 256-bit chain code
- Extended public keys (xpub): Public key with chain code for generating child public keys
- Child key derivation (CKD) functions for both normal and hardened derivations
- Complete path derivation using the `m/purpose'/coin_type'/account'/change/address_index` structure

### Elliptic Curve Cryptography

It uses secp256k1 elliptic curve (the same used in Bitcoin) and implements HMAC-SHA512 for key generation. There's scope for secure random number generation for entropy collection.

### Mnemonic Implementation

The BIP39 mnemonic implementation includes entropy generation with configurable security levels (128, 160, 192, 224, or 256 bits), conversion of entropy to a mnemonic sentence using a wordlist, optional passphrase support for additional security and deterministic generation of a binary seed from the mnemonic

## Address Types

HDWallet-secp256k1 supports multiple address derivation schemes:

| Address Type | Description | Path Template | Prefix |
|--------------|-------------|---------------|--------|
| P2PKH | Legacy Bitcoin addresses | m/44'/0'/0'/0/n | 1 |
| P2SH-P2WPKH | SegWit-compatible (nested) | m/49'/0'/0'/0/n | 3 |
| P2WPKH | Native SegWit | m/84'/0'/0'/0/n | bc1 |
| Ethereum | Ethereum addresses | m/44'/60'/0'/0/n | 0x |

## Secure Storage Architecture

HDWallet-secp256k1's storage subsystem provides encrypted at-rest storage of sensitive wallet data, pw-based key derivation function (PBKDF2) for encryption key generation and AES-256-GCM authenticated encryption for wallet data.