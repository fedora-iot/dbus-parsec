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

use std::env;

use dbus::ffidisp::{Connection, NameFlag};
use dbus::message::Message;
use dbus::tree;
use dbus::tree::{Factory, Interface, MTFn};

use parsec_client::auth::AuthenticationData;
use parsec_client::core::interface::requests::Opcode;
use parsec_client::core::secrecy::Secret;
use parsec_client::BasicClient;

mod agent;
mod utils;

mod nm_secretagent {
    include!(concat!(env!("OUT_DIR"), "/nm_secretagent.rs"));
}

mod dbus_parsec_control_server {
    include!(concat!(env!("OUT_DIR"), "/dbus_parsec_control_server.rs"));
}

mod dbus_parsec_control_client {
    include!(concat!(env!("OUT_DIR"), "/dbus_parsec_control_client.rs"));
}

use agent::{Agent, Config};

#[derive(Copy, Clone, Default, Debug)]
struct TData;
impl tree::DataType for TData {
    type Tree = Agent;
    type ObjectPath = ();
    type Property = ();
    type Interface = ();
    type Method = ();
    type Signal = ();
}

fn create_nm_sa_iface() -> Interface<MTFn<TData>, TData> {
    let f = tree::Factory::new_fn();
    nm_secretagent::org_freedesktop_network_manager_secret_agent_server(&f, (), |m| {
        let a: &Agent = m.tree.get_data();
        a
    })
}

fn create_dbus_parsec_control_iface() -> Interface<MTFn<TData>, TData> {
    let f = tree::Factory::new_fn();
    dbus_parsec_control_server::com_github_puiterwijk_dbus_parseccontrol_server(&f, (), |m| {
        let a: &Agent = m.tree.get_data();
        a
    })
}

static NM_SA_OBJ_PATH: &str = "/org/freedesktop/NetworkManager/SecretAgent";
static DBUS_PARSEC_CONTROL_OBJ_PATH: &str = "/com/github/puiterwijk/DBusPARSEC/Control";
static DBUS_NAME: &str = "com.github.puiterwijk.dbus_parsec";

static NM_DBUS_NAME: &str = "org.freedesktop.NetworkManager";
static NM_AGENTMANAGER_OBJ_PATH: &str = "/org/freedesktop/NetworkManager/AgentManager";
static NM_AGENTMANAGER_IFACE: &str = "org.freedesktop.NetworkManager.AgentManager";

fn register_to_nm_am(conn: &Connection) -> Result<(), dbus::Error> {
    let req = Message::method_call(
        &dbus::strings::BusName::from(NM_DBUS_NAME),
        &dbus::strings::Path::from(NM_AGENTMANAGER_OBJ_PATH),
        &dbus::strings::Interface::from(NM_AGENTMANAGER_IFACE),
        &dbus::strings::Member::from("Register"),
    )
    .append1(DBUS_NAME);
    let mut res = conn.send_with_reply_and_block(req, 1000)?;
    res.as_result()?;

    Ok(())
}

fn init_parsec() -> Result<BasicClient, Error> {
    let app_name = String::from("dbus_parsec");
    let app_auth_data = AuthenticationData::AppIdentity(Secret::new(app_name));
    let mut client: BasicClient = BasicClient::new(app_auth_data);

    client.ping()?;
    let providers = client.list_providers()?;
    if providers.len() < 2 {
        return Err(Error::ParsecFeatureUnavailable("Any crypto provider"));
    }
    let used_provider = providers[0].id;
    let opcodes = client.list_opcodes(used_provider)?;
    if !opcodes.contains(&Opcode::PsaSignHash) {
        return Err(Error::ParsecFeatureUnavailable("PsaSignHash"));
    }
    if !opcodes.contains(&Opcode::PsaGenerateKey) {
        return Err(Error::ParsecFeatureUnavailable("psaGenerateKey"));
    }
    if !opcodes.contains(&Opcode::PsaExportPublicKey) {
        return Err(Error::ParsecFeatureUnavailable("PsaExportPublicKey"));
    }
    if !opcodes.contains(&Opcode::PsaAsymmetricDecrypt) {
        return Err(Error::ParsecFeatureUnavailable("PsaAsymmetricDecrypt"));
    }
    client.set_implicit_provider(used_provider);

    Ok(client)
}

#[derive(Debug)]
enum Error {
    Configuration(&'static str),
    ParsecClient(parsec_client::error::Error),
    ParsecFeatureUnavailable(&'static str),
    DBus(dbus::Error),
}

impl From<parsec_client::error::Error> for Error {
    fn from(parsec_error: parsec_client::error::Error) -> Self {
        Error::ParsecClient(parsec_error)
    }
}

impl From<dbus::Error> for Error {
    fn from(dbus_error: dbus::Error) -> Self {
        Error::DBus(dbus_error)
    }
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Configuration(msg) => {
                write!(f, "Configuration error: {}", msg)
            }
            Error::ParsecFeatureUnavailable(feature) => {
                write!(f, "PARSEC feature unavailable: {}", feature)
            }
            Error::ParsecClient(err) => {
                write!(f, "PARSEC Client Error: ")?;
                err.fmt(f)
            }
            Error::DBus(err) => {
                write!(f, "DBus Error: ")?;
                err.fmt(f)
            }
        }
    }
}

fn get_config() -> Result<Config, Error> {
    let unique_keys = env::var("NO_UNIQUE_KEYS").is_err();
    let storage_dir = match env::var("STORAGE_DIR") {
        Ok(dir) => dir,
        Err(_) => return Err(Error::Configuration("No STORAGE_DIR provided")),
    };

    Ok(Config::new(&storage_dir, unique_keys))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = init_parsec()?;
    let config = get_config()?;
    let agent = Agent::new(config, client);
    run_dbus(agent)?;
    Ok(())
}

fn run_dbus(agent: Agent) -> Result<(), Error> {
    let f = Factory::new_fn();
    let nm_sa_intf = create_nm_sa_iface();
    let dbus_parsec_control_intf = create_dbus_parsec_control_iface();
    let tree = f
        .tree(agent)
        .add(
            f.object_path(NM_SA_OBJ_PATH, ())
                .introspectable()
                .add(nm_sa_intf),
        )
        .add(
            f.object_path(DBUS_PARSEC_CONTROL_OBJ_PATH, ())
                .introspectable()
                .add(dbus_parsec_control_intf),
        );

    let conn = Connection::new_system()?;
    conn.register_name(
        DBUS_NAME,
        NameFlag::DoNotQueue.value() | NameFlag::ReplaceExisting.value(),
    )?;
    tree.set_registered(&conn, true)?;
    conn.add_handler(tree);
    register_to_nm_am(&conn)?;

    eprintln!("Running");

    loop {
        conn.incoming(1000).next();
    }
}
