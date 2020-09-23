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

use std::collections::HashMap;

use dbus::arg;
use dbus::tree::MethodErr;

use crate::nm_secretagent;

use super::Agent;
use super::KeyType;

fn str_refarg(input: String) -> arg::Variant<Box<dyn arg::RefArg + 'static>> {
    arg::Variant(Box::new(input))
}

fn vpn_plugin_remove_prefix(plugin: &str) -> &str {
    plugin.trim_start_matches("org.freedesktop.NetworkManager.")
}

// Source: NetworkManager/clients/common/nm-vpn-helpers.c:nm_vpn_get_secret_names
fn networkmanager_vpn_applicable_secrets(plugin: &str) -> Option<&[&'static str]> {
    match vpn_plugin_remove_prefix(plugin) {
        "pptp" | "iodine" | "ssh" | "l2tp" | "fortisslvpn" => Some(&["password"]),
        "openvpn" => Some(&["password", "cert-pass", "http-proxy-password"]),
        "vpnc" => Some(&["Xauth password", "IPSec secret"]),
        "openswan" | "libreswan" | "strongswan" => Some(&["xauthpassword", "pskvalue"]),
        "openconnect" => Some(&["gateway", "cookie", "gwcert"]),
        _ => None,
    }
}

#[derive(Debug)]
enum NMWirelessType {
    PSK,
    Enterprise,
}

impl NMWirelessType {
    fn get_applicable_secrets(&self) -> Option<&[&'static str]> {
        match self {
            NMWirelessType::PSK => Some(&["psk"]),
            NMWirelessType::Enterprise => Some(&["password"]),
        }
    }

    fn secret_toplevel_name(&self) -> &'static str {
        match self {
            NMWirelessType::PSK => "802-11-wireless-security",
            NMWirelessType::Enterprise => "802-1x",
        }
    }
}

#[derive(Debug)]
enum NetworkManagerConnectionType<'a> {
    Vpn(&'a str),
    Wireguard,
    Wireless(NMWirelessType),
}

impl<'a> NetworkManagerConnectionType<'a> {
    fn get_applicable_secrets(&self) -> Option<&[&'static str]> {
        match self {
            NetworkManagerConnectionType::Vpn(vpntype) => {
                networkmanager_vpn_applicable_secrets(vpntype)
            }
            NetworkManagerConnectionType::Wireguard => Some(&["private-key"]),
            NetworkManagerConnectionType::Wireless(wltype) => wltype.get_applicable_secrets(),
        }
    }

    fn secret_toplevel_name(&self) -> &'static str {
        match self {
            NetworkManagerConnectionType::Vpn(_) => "vpn",
            NetworkManagerConnectionType::Wireguard => "wireguard",
            NetworkManagerConnectionType::Wireless(wltype) => wltype.secret_toplevel_name(),
        }
    }
}

type NMConnection<'a> = HashMap<&'a str, HashMap<&'a str, arg::Variant<Box<dyn arg::RefArg>>>>;
type NMSecretValues<'a> = HashMap<String, arg::Variant<Box<dyn arg::RefArg + 'static>>>;
type NMSecrets<'a> = HashMap<String, NMSecretValues<'a>>;

trait NMConnectionInfo<'a> {
    fn get_nm_id(&'a self) -> Option<&'a str>;
    fn get_conn_type(&'a self) -> Option<NetworkManagerConnectionType<'a>>;
}

impl<'a> NMConnectionInfo<'a> for &NMConnection<'a> {
    fn get_nm_id(&'a self) -> Option<&'a str> {
        self.get("connection")?.get("id")?.0.as_str()
    }

    fn get_conn_type(&'a self) -> Option<NetworkManagerConnectionType<'a>> {
        match self.get("connection")?.get("type")?.0.as_str()? {
            "vpn" => Some(NetworkManagerConnectionType::Vpn(
                self.get("vpn")?.get("service-type")?.0.as_str()?,
            )),
            "wireguard" => Some(NetworkManagerConnectionType::Wireguard),
            "802-11-wireless" => match self.get("802-11-wireless-security")?.get("key-mgmt")?.0.as_str()? {
                "wpa-psk" => Some(NetworkManagerConnectionType::Wireless(NMWirelessType::PSK)),
                _ => Some(NetworkManagerConnectionType::Wireless(NMWirelessType::Enterprise)),
            },
            _ => None,
        }
    }
}

#[derive(Debug)]
enum NMSecretAgentFlag {
    #[allow(dead_code)]
    None,

    AgentOwned,

    NotSaved,

    #[allow(dead_code)]
    NotRequired,
}

impl NMSecretAgentFlag {
    fn get_value(&self) -> u32 {
        match self {
            NMSecretAgentFlag::None => 0x0,
            NMSecretAgentFlag::AgentOwned => 0x1,
            NMSecretAgentFlag::NotSaved => 0x2,
            NMSecretAgentFlag::NotRequired => 0x4,
        }
    }
}

trait FlagSet<FlagType> {
    fn flag_set(&self, flag: FlagType) -> bool;
}

impl FlagSet<NMSecretAgentFlag> for u32 {
    fn flag_set(&self, flag: NMSecretAgentFlag) -> bool {
        self & flag.get_value() != 0
    }
}

impl nm_secretagent::OrgFreedesktopNetworkManagerSecretAgent for Agent {
    fn get_secrets(
        &self,
        connection: NMConnection,
        _connection_path: dbus::Path,
        _setting_name: &str,
        _hints: Vec<&str>,
        flags: u32,
    ) -> Result<NMSecrets, MethodErr> {
        if flags.flag_set(NMSecretAgentFlag::NotSaved) {
            eprintln!("We were told that we can't use a saved secret");
            return Err(MethodErr::failed("Unwilling to return non-saved secrets"));
        }
        if flags.flag_set(NMSecretAgentFlag::AgentOwned) {
            eprintln!("We were told that we have to generate and store a secret");
            //return Err(MethodErr::failed("Unwilling to ask for new secret"));
        }

        //eprintln!("Got a call to get_secrets. connection: {:?}, connection_path: {:?}, setting_name: {:?}, hints: {:?}, flags: {:?}", connection, connection_path, setting_name, hints, flags);

        let connection = &connection;
        let conn_name = match connection.get_nm_id() {
            Some(id) => id,
            None => return Err(MethodErr::failed("Invalid Connection object: no id")),
        };
        let conn_type = match connection.get_conn_type() {
            Some(ctype) => ctype,
            None => {
                return Err(MethodErr::failed(
                    "Invalid connection object: unrecognized connection type",
                ))
            }
        };

        let secret_names = match conn_type.get_applicable_secrets() {
            Some(secret_names) => secret_names,
            None => return Err(MethodErr::failed("Unknown connection type")),
        };

        let secret_values: NMSecretValues = secret_names
            .iter()
            .map(|secret_name| {
                (
                    *secret_name,
                    self.retrieve_secret(&KeyType::NetworkManager, conn_name, secret_name),
                )
            })
            .filter(|x| x.1.is_some())
            .map(|x| (x.0.to_string(), String::from_utf8(x.1.unwrap())))
            .filter(|x| x.1.is_ok())
            .map(|x| (x.0, str_refarg(x.1.unwrap())))
            .collect();

        let mut secrets = HashMap::new();
        secrets.insert(conn_type.secret_toplevel_name().to_string(), secret_values);
        Ok(secrets)
    }

    fn cancel_get_secrets(
        &self,
        _connection_path: dbus::Path,
        _setting_name: &str,
    ) -> Result<(), MethodErr> {
        Err(MethodErr::failed("Not implemented"))
    }

    fn save_secrets(
        &self,
        _connection: NMConnection,
        _connection_path: dbus::Path,
    ) -> Result<(), MethodErr> {
        Err(MethodErr::failed("Not implemented"))
    }

    fn delete_secrets(
        &self,
        _connection: NMConnection,
        _connection_path: dbus::Path,
    ) -> Result<(), MethodErr> {
        Err(MethodErr::failed("Not implemented"))
    }
}
