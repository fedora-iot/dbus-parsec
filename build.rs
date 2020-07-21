use std::env;
use std::fs;
use std::path::Path;

use dbus_codegen;

const NM_SA_XML: &str =
    "/usr/share/dbus-1/interfaces/org.freedesktop.NetworkManager.SecretAgent.xml";

const DBUS_PARSEC_CONTROL_XML: &str = "src/com.github.puiterwijk.DBusPARSEC.control.xml";

fn main() {
    let pkg_dir = env!("CARGO_MANIFEST_DIR");
    let pkg_dir = Path::new(pkg_dir);
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);

    let codegen_opts = dbus_codegen::GenOpts {
        dbuscrate: "dbus".to_string(),
        connectiontype: dbus_codegen::ConnectionType::Ffidisp,
        serveraccess: dbus_codegen::ServerAccess::RefClosure,
        methodtype: Some("MTFn".to_string()),
        genericvariant: true,

        crhandler: None,
        skipprefix: None,
        futures: false,
        interfaces: None,
        command_line: "build.rs".to_string(),
    };

    println!("cargo:rerun-if-changed={}", NM_SA_XML);
    let nm_sa_iface =
        fs::read_to_string(NM_SA_XML).expect("Error reading NetworkManager SecretAgent interface");
    let nm_sa_gen = dbus_codegen::generate(&nm_sa_iface, &codegen_opts)
        .expect("Error generating NetworkManager SecretAgent code");
    std::fs::write(out_dir.join("nm_secretagent.rs"), nm_sa_gen)
        .expect("Error writing generated NetworkManager SecretAgent interface");

    println!("cargo:rerun-if-changed={}", DBUS_PARSEC_CONTROL_XML);
    let dbus_parsec_control_iface =
        fs::read_to_string(pkg_dir.join(DBUS_PARSEC_CONTROL_XML)).expect("Error reading control interface");
    let dbus_parsec_control_gen = dbus_codegen::generate(&dbus_parsec_control_iface, &codegen_opts)
        .expect("Error generting control code");
    std::fs::write(out_dir.join("dbus_parsec_control.rs"), dbus_parsec_control_gen)
        .expect("Error writing control code");
}
