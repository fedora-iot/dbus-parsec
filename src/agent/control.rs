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
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use dbus::tree::MethodErr;

use crate::dbus_parsec_control_server;

use super::Agent;
use super::KeyType;

impl dbus_parsec_control_server::ComGithubPuiterwijkDBusPARSECControl for Agent {
    fn get_public_key(&self, secret_type: &str, secret_group: &str) -> Result<Vec<u8>, MethodErr> {
        let key_name = match KeyType::from_type(secret_type) {
            None => {
                return Err(MethodErr::failed(&format!(
                    "Unrecognized secret type: {}",
                    secret_type
                )))
            }
            Some(key_id) => self.key_name(&key_id, secret_group),
        };

        match self.parsec_client.psa_export_public_key(key_name.clone()) {
            Ok(key) => Ok(key),
            Err(parsec_client::error::Error::Service(
                parsec_client::core::interface::requests::ResponseStatus::PsaErrorDoesNotExist,
            )) => {
                eprintln!("Creating new key: {}", &key_name);

                match self.create_key(&key_name) {
                    Ok(_) => self
                        .parsec_client
                        .psa_export_public_key(key_name.clone())
                        .map_err(|err| {
                            MethodErr::failed(&format!(
                                "Unexpected error getting key after creating: {}",
                                err
                            ))
                        }),
                    Err(err) => Err(MethodErr::failed(&format!(
                        "Unexpected error creating new key: {}",
                        err
                    ))),
                }
            }
            Err(err) => Err(MethodErr::failed(&format!("Unexpected error: {}", err))),
        }
    }

    fn store_secret(
        &self,
        secret_type: &str,
        secret_group: &str,
        secret_name: &str,
        wrapper_key: Vec<u8>,
        secret_value: Vec<u8>,
    ) -> Result<(), MethodErr> {
        let secret_type = match KeyType::from_type(secret_type) {
            None => {
                return Err(MethodErr::failed(&format!(
                    "Unrecognized secret type: {}",
                    secret_type
                )))
            }
            Some(key_id) => key_id,
        };
        let (wrapkey_path, contents_path) =
            self.get_secret_file_paths(&secret_type, secret_group, secret_name)?;

        // Try to decrypt the secret to ensure we're not being passed nonsense
        match self.decrypt_secret(
            &secret_type,
            secret_group,
            secret_name,
            &wrapper_key,
            &secret_value,
        ) {
            Some(_) => {}
            None => return Err(MethodErr::failed("Unable to decrypt secret")),
        };

        let err_failed = MethodErr::failed("Unable to write secret");

        let mut wrapkey_file = fs::File::create(wrapkey_path).map_err(|_| err_failed.clone())?;
        let mut perms = wrapkey_file
            .metadata()
            .map_err(|_| err_failed.clone())?
            .permissions();
        perms.set_mode(0o600);
        wrapkey_file
            .set_permissions(perms)
            .map_err(|_| err_failed.clone())?;
        wrapkey_file.sync_all().map_err(|_| err_failed.clone())?;

        let mut contents_file = fs::File::create(contents_path).map_err(|_| err_failed.clone())?;
        let mut perms = contents_file
            .metadata()
            .map_err(|_| err_failed.clone())?
            .permissions();
        perms.set_mode(0o600);
        contents_file
            .set_permissions(perms)
            .map_err(|_| err_failed.clone())?;
        contents_file.sync_all().map_err(|_| err_failed.clone())?;

        wrapkey_file
            .write_all(&wrapper_key)
            .map_err(|_| err_failed.clone())?;
        contents_file
            .write_all(&secret_value)
            .map_err(|_| err_failed.clone())?;

        wrapkey_file.sync_all().map_err(|_| err_failed.clone())?;
        contents_file.sync_all().map_err(|_| err_failed.clone())?;

        Ok(())
    }
}
