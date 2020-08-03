// Copyright 2020 Patrick Uiterwijk
//
// Licensed under the EUPL-1.2-or-later
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::path;
use std::fs;

use parsec_client::core::interface::operations::psa_algorithm::{AsymmetricEncryption, Hash};
use parsec_client::core::interface::operations::psa_key_attributes::{
    Attributes, Lifetime, Policy, Type, UsageFlags,
};
use parsec_client::BasicClient;

use ring::aead::Aad;
use ring::aead::LessSafeKey;
use ring::aead::Nonce;
use ring::aead::UnboundKey;
use ring::aead::AES_256_GCM;

use dbus::tree::MethodErr;

mod control;
mod networkmanager;

#[derive(Debug)]
pub struct Config {
    storagedir: path::PathBuf,
    uniquekeys: bool,
}

impl Config {
    pub fn new(storagedir: &str, uniquekeys: bool) -> Self {
        Config {
            storagedir: storagedir.to_string().into(),
            uniquekeys,
        }
    }
}

static SPLITCHAR: &str = "_";

fn is_valid_identifier(ident: &str) -> bool {
    !ident.contains(SPLITCHAR)
}

enum KeyType {
    NetworkManager,
}

impl KeyType {
    fn from_type(secret_type: &str) -> Option<Self> {
        match secret_type.to_lowercase().as_str() {
            "networkmanager" => Some(KeyType::NetworkManager),
            _ => None,
        }
    }

    fn to_type(&self) -> &str {
        match self {
            KeyType::NetworkManager => "networkmanager",
        }
    }

    fn key_name(&self, secret_group: &str) -> String {
        match self {
            KeyType::NetworkManager => format!("networkmanager-{}", secret_group),
        }
    }
}

#[derive(Debug)]
pub struct Agent {
    parsec_client: BasicClient,
    config: Config,
}

impl Agent {
    pub fn new(config: Config, parsec_client: BasicClient) -> Self {
        Agent {
            config,
            parsec_client,
        }
    }

    fn key_name(&self, keytype: &KeyType, secret_group: &str) -> String {
        if !self.config.uniquekeys {
            "encryption_key".to_string()
        } else {
            keytype.key_name(secret_group)
        }
    }

    // Returns (wrapkey_path, contents_path)
    fn get_secret_file_paths(
        &self,
        secret_type: &KeyType,
        secret_group: &str,
        secret_name: &str,
    ) -> Result<(path::PathBuf, path::PathBuf), MethodErr> {
        if !is_valid_identifier(secret_group) || !is_valid_identifier(secret_name) {
            Err(MethodErr::failed("Invalid secret identifiers"))
        } else {
            let file_base = format!(
                "secret{}{}{}{}{}{}",
                SPLITCHAR,
                secret_type.to_type(),
                SPLITCHAR,
                secret_group,
                SPLITCHAR,
                secret_name
            );
            Ok((
                self.config
                    .storagedir
                    .join(format!("{}.wrapkey", file_base)),
                self.config
                    .storagedir
                    .join(format!("{}.contents", file_base)),
            ))
        }
    }

    fn create_key(&self, key_name: &str) -> Result<(), parsec_client::error::Error> {
        let asym_enc_algo = AsymmetricEncryption::RsaOaep {
            hash_alg: Hash::Sha256,
        };

        let key_attrs = Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::RsaKeyPair,
            bits: 2048,
            policy: Policy {
                usage_flags: UsageFlags {
                    export: false,
                    copy: false,
                    cache: false,
                    encrypt: true,
                    decrypt: true,
                    sign_message: false,
                    verify_message: false,
                    sign_hash: false,
                    verify_hash: false,
                    derive: false,
                },
                permitted_algorithms: asym_enc_algo.into(),
            },
        };

        self.parsec_client
            .psa_generate_key(key_name.to_string(), key_attrs)?;

        Ok(())
    }

    fn retrieve_secret(&self, secret_type: &KeyType, secret_group: &str, secret_name: &str) -> Option<Vec<u8>> {
        let (wrapkey_path, contents_path) = match self.get_secret_file_paths(secret_type, secret_group, secret_name) {
            Ok(res) => res,
            Err(_) => return None,
        };
        let wrapkey = match fs::read(&wrapkey_path) {
            Ok(res) => res,
            Err(err) => {
                eprintln!("Error reading wrapkey {:?}: {}", wrapkey_path, err);
                return None;
            },
        };
        let contents = match fs::read(&contents_path) {
            Ok(res) => res,
            Err(err) => {
                eprintln!("Error reading contents {:?}: {}", contents_path, err);
                return None;
            }
        };
        self.decrypt_secret(secret_type, secret_group, secret_name, &wrapkey, &contents)
    }

    fn decrypt_secret(
        &self,
        secret_type: &KeyType,
        secret_group: &str,
        secret_name: &str,
        wrapkey: &[u8],
        value: &[u8],
    ) -> Option<Vec<u8>> {
        let key_name = self.key_name(secret_type, secret_group);
        let asym_enc_algo = AsymmetricEncryption::RsaOaep {
            hash_alg: Hash::Sha256,
        };

        let plain_wrapper =
            match self
                .parsec_client
                .psa_asymmetric_decrypt(key_name, asym_enc_algo, wrapkey, None)
            {
                Ok(key) => key,
                Err(err) => {
                    eprintln!("Error decrypting wrapper key: {}", err);
                    return None;
                }
            };

        let aad = format!("{};{};{}", secret_type.to_type(), secret_group, secret_name);
        let aad = Aad::from(aad);

        let nonce = &plain_wrapper[0..12];
        let plain_wrapkey = &plain_wrapper[12..];

        let nonce = match Nonce::try_assume_unique_for_key(nonce) {
            Ok(nonce) => nonce,
            Err(err) => {
                eprintln!("Nonce not assumed unique: {}", err);
                return None;
            }
        };
        let plain_wrapkey = match UnboundKey::new(&AES_256_GCM, &plain_wrapkey) {
            Ok(key) => key,
            Err(err) => {
                eprintln!("Wrapkey invalid: {}", err);
                return None;
            }
        };

        let mut in_out = value.to_vec();

        let wrapkey = LessSafeKey::new(plain_wrapkey);

        let plaintext = match wrapkey.open_in_place(nonce, aad, &mut in_out) {
            Ok(pt) => pt,
            Err(err) => {
                eprintln!("Error decrypting inner contents: {}", err);
                return None;
            }
        };

        Some(plaintext.to_vec())
    }
}
