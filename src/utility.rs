static DBUS_PARSEC_CONTROL_OBJ_PATH: &str = "/com/github/puiterwijk/DBusPARSEC/Control";
static DBUS_NAME: &str = "com.github.puiterwijk.dbus_parsec";

use anyhow::{ensure, Context, Result};
use openssl::{
    hash::{hash, MessageDigest},
    rsa::Rsa,
};

use std::env;
use std::io::{self, Read};

use dbus::blocking::Connection;
use std::time::Duration;

use dbus_parsec_control::ComGithubPuiterwijkDBusPARSECControl;

mod crypto;
mod dbus_parsec_control {
    include!(concat!(env!("OUT_DIR"), "/dbus_parsec_control_client.rs"));
}

fn sha256_hex(inp: &[u8]) -> Result<String> {
    hash(MessageDigest::sha256(), inp)
        .context("Error computing sha256")
        .map(hex::encode)
}

fn read_input_token() -> Result<String> {
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .with_context(|| "Unable to read secret")?;
    let buffer = String::from(buffer.trim());
    ensure!(!buffer.is_empty(), "No data provided");
    Ok(buffer)
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    ensure!(
        args.len() == 5 && args[1] == "prime",
        "Usage: {} prime <secret-type> <secret-group> <secret-name>",
        args[0]
    );
    let (secret_type, secret_group, secret_name) = (&args[2], &args[3], &args[4]);
    let secret = read_input_token().with_context(|| "Error getting secret contents")?;
    let secret = secret.into_bytes();

    let conn = Connection::new_system().with_context(|| "Unable to connect to DBus System Bus")?;
    let proxy = conn.with_proxy(
        DBUS_NAME,
        DBUS_PARSEC_CONTROL_OBJ_PATH,
        Duration::from_millis(5000),
    );

    // Let's get the pubkey first, so we know the control interface is reachable
    let pubkey = proxy
        .get_public_key(&secret_type, &secret_group)
        .with_context(|| {
            format!(
                "Unable to get public key for secret type {}, group {}",
                &secret_type, &secret_group
            )
        })?;
    println!("Public key sha256: {}", sha256_hex(&pubkey)?);
    let pubkey = Rsa::public_key_from_der_pkcs1(&pubkey).context("Unable to parse public key")?;

    let encrypt_result =
        crate::crypto::encrypt_secret(&pubkey, &secret_type, &secret_group, &secret_name, secret)
            .context("Error encrypting secret")?;

    // Store the secret finally
    proxy
        .store_secret(
            secret_type,
            secret_group,
            secret_name,
            encrypt_result.wrapped_wrapkey,
            encrypt_result.secret,
        )
        .with_context(|| format!("Failed to store secret {}", &secret_name))?;

    println!("Secret stored");

    Ok(())
}
