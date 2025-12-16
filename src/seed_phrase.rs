use std::str::FromStr;

use stellar_strkey::ed25519::{PrivateKey, PublicKey};

use crate::error::Error;

pub struct KeyPair(slip10::Key);

impl KeyPair {
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.public_key()[1..].try_into().unwrap())
    }

    pub fn private(&self) -> PrivateKey {
        PrivateKey(self.0.key)
    }
}

impl From<slip10::Key> for KeyPair {
    fn from(value: slip10::Key) -> Self {
        KeyPair(value)
    }
}

#[derive(Clone, Debug)]
pub struct SeedPhrase {
    pub curve: slip10::Curve,
    pub seed_phrase: bip39::Mnemonic,
}

impl SeedPhrase {
    pub fn new_ed25519(seed_phrase: bip39::Mnemonic) -> Self {
        Self {
            curve: slip10::Curve::Ed25519,
            seed_phrase,
        }
    }

    /// Uses passed entropy to generate the seed phrase
    pub fn from_entropy(bytes: &[u8]) -> Result<Self, Error> {
        let res = bip39::Mnemonic::from_entropy(bytes, bip39::Language::English)?;
        Ok(Self::new_ed25519(res))
    }

    /// Creates a `SeedPhrase` using a `seed_phrase`, which is
    /// trimmed and enusures that only one space between words.
    pub fn from_seed_phrase(seed_phrase: &str) -> Result<Self, Error> {
        let seed_phrase = seed_phrase.split_whitespace().collect::<Vec<_>>().join(" ");

        let res = bip39::Mnemonic::from_phrase(&seed_phrase, bip39::Language::English)?;
        Ok(Self::new_ed25519(res))
    }

    /// Generate a random seed phrase of various lengths
    pub fn random(mtype: bip39::MnemonicType) -> Result<Self, Error> {
        Ok(Self::new_ed25519(bip39::Mnemonic::new(
            mtype,
            bip39::Language::English,
        )))
    }

    /// inner string representing the seed phrase
    pub fn phrase(&self) -> &str {
        self.seed_phrase.phrase()
    }

    /// bip39 `Seed` used to generate key with slip10
    pub fn to_seed(&self, passphrase: Option<&str>) -> bip39::Seed {
        bip39::Seed::new(&self.seed_phrase, passphrase.unwrap_or_default())
    }

    /// Generate a key from a path string, anything after `m/44'/148'`
    pub fn from_path_string(&self, path: &str, passphrase: Option<&str>) -> Result<KeyPair, Error> {
        let path = format!("m/44'/148'{path}");
        Ok(slip10::derive_key_from_path(
            self.to_seed(passphrase).as_bytes(),
            self.curve,
            &slip10::BIP32Path::from_str(&path)
                .map_err(|_| Error::InvalidIndex { path: path.clone() })?,
        )
        .map_err(|_| Error::InvalidIndex { path })?
        .into())
    }

    /// Generate a key from a path index, anything after `m/44'/148'/{num}'`
    pub fn from_path_index(&self, num: usize, passphrase: Option<&str>) -> Result<KeyPair, Error> {
        self.from_path_string(&format!("/{num}'"), passphrase)
    }

    /// Generate key pair from path `m/44'/148'`.
    pub fn empty_key(&self, passphrase: Option<&str>) -> Result<KeyPair, Error> {
        self.from_path_string("", passphrase)
    }
}

impl From<SeedPhrase> for bip39::Seed {
    fn from(seed_phrase: SeedPhrase) -> Self {
        seed_phrase.to_seed(None)
    }
}

impl FromStr for SeedPhrase {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_seed_phrase(s)
    }
}
