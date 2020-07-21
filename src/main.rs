use dbus::ffidisp::{Connection, NameFlag};
use dbus::message::Message;
use dbus::tree;
use dbus::tree::{Factory, Interface, MTFn};

use parsec_client::auth::AuthenticationData;
use parsec_client::core::interface::requests::Opcode;
use parsec_client::core::interface::requests::ProviderID;
use parsec_client::core::secrecy::Secret;
use parsec_client::BasicClient;

use uuid::Uuid;

mod agent;

mod nm_secretagent {
    include!(concat!(env!("OUT_DIR"), "/nm_secretagent.rs"));
}

mod dbus_parsec_control {
    include!(concat!(env!("OUT_DIR"), "/dbus_parsec_control.rs"));
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
    dbus_parsec_control::com_github_puiterwijk_dbus_parseccontrol_server(&f, (), |m| {
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
    let tpmuuid = Uuid::parse_str("1e4954a4-ff21-46d3-ab0c-661eeb667e1d").unwrap();
    let used_provider = ProviderID::MbedCrypto;

    let app_name = String::from("dbus_parsec");
    let app_auth_data = AuthenticationData::AppIdentity(Secret::new(app_name));
    let mut client: BasicClient = BasicClient::new(app_auth_data);

    client.ping()?;
    if client
        .list_providers()?
        .iter()
        .filter(|p| p.uuid == tpmuuid)
        .count()
        == 0
    {
        //return Err(Error::ParsecFeatureUnavailable("TPM Provider"));
    }
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = init_parsec()?;
    // TODO
    let config = Config::new(ProviderID::MbedCrypto, "/tmp/dbus-parsec", true);
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
