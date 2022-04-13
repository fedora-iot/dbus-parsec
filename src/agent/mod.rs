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

use std::fs;
use std::path;

use anyhow::{bail, Context, Result};
use parsec_client::core::interface::operations::psa_algorithm::{AsymmetricEncryption, Hash};
use parsec_client::core::interface::operations::psa_key_attributes::{
    Attributes, Lifetime, Policy, Type, UsageFlags,
};
use parsec_client::BasicClient;

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
    ) -> Result<(path::PathBuf, path::PathBuf)> {
        if !is_valid_identifier(secret_group) || !is_valid_identifier(secret_name) {
            bail!("Invalid secret identifiers");
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

        let mut usage_flags = UsageFlags::default();
        usage_flags.set_encrypt().set_decrypt();

        let key_attrs = Attributes {
            lifetime: Lifetime::Persistent,
            key_type: Type::RsaKeyPair,
            bits: 2048,
            policy: Policy {
                usage_flags: usage_flags,
                permitted_algorithms: asym_enc_algo.into(),
            },
        };

        self.parsec_client.psa_generate_key(key_name, key_attrs)?;

        Ok(())
    }

    fn retrieve_secret(
        &self,
        secret_type: &KeyType,
        secret_group: &str,
        secret_name: &str,
    ) -> Result<Vec<u8>> {
        let (wrapkey_path, contents_path) = self
            .get_secret_file_paths(secret_type, secret_group, secret_name)
            .context("Error determining secret file path")?;
        let wrapkey = fs::read(&wrapkey_path).context("Error reading wrapkey")?;
        let contents = fs::read(&contents_path).context("Error reading secret contents")?;
        self.decrypt_secret(secret_type, secret_group, secret_name, &wrapkey, &contents)
            .context("Error decrypting secret")
    }

    fn decrypt_secret(
        &self,
        secret_type: &KeyType,
        secret_group: &str,
        secret_name: &str,
        wrapkey: &[u8],
        value: &[u8],
    ) -> Result<Vec<u8>> {
        let key_name = self.key_name(secret_type, secret_group);
        let asym_enc_algo = AsymmetricEncryption::RsaOaep {
            hash_alg: Hash::Sha256,
        };

        let wrapkey = self
            .parsec_client
            .psa_asymmetric_decrypt(&key_name, asym_enc_algo, wrapkey, None)
            .context("Error decrypting wrapkey")?;

        crate::crypto::decrypt_secret(
            wrapkey,
            &secret_type.to_type(),
            secret_group,
            secret_name,
            value,
        )
        .context("Error decrypting secret")
    }
}
