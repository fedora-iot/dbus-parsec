static DBUS_PARSEC_CONTROL_OBJ_PATH: &str = "/com/github/puiterwijk/DBusPARSEC/Control";
static DBUS_NAME: &str = "com.github.puiterwijk.dbus_parsec";

use anyhow::{ensure, Context, Result};

use rsa::{PaddingScheme, PublicKey, RSAPublicKey};

use rand::rngs::OsRng;

use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};

use sha2::{Digest, Sha256};

use std::env;
use std::io::{self, Read};

use dbus::blocking::Connection;
use std::time::Duration;

use dbus_parsec_control::ComGithubPuiterwijkDBusPARSECControl;

mod utils;

mod dbus_parsec_control {
    include!(concat!(env!("OUT_DIR"), "/dbus_parsec_control_client.rs"));
}

fn sha256_hex(inp: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(inp);
    let result = hasher.finalize();
    hex::encode(result)
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
    let mut secret = secret.into_bytes();

    let conn = Connection::new_system().with_context(|| "Unable to connect to DBus System Bus")?;
    let proxy = conn.with_proxy(
        DBUS_NAME,
        DBUS_PARSEC_CONTROL_OBJ_PATH,
        Duration::from_millis(5000),
    );

    // We need multiple random sources...
    let sysrand = SystemRandom::new();
    let mut rsarand = OsRng;

    // Let's get the pubkey first, so we know the control interface is reachable
    let pubkey = proxy
        .get_public_key(&secret_type, &secret_group)
        .with_context(|| {
            format!(
                "Unable to get public key for secret type {}, group {}",
                &secret_type, &secret_group
            )
        })?;
    println!("Public key sha256: {}", sha256_hex(&pubkey));
    let pubkey = RSAPublicKey::from_pkcs1(&pubkey)
        .with_context(|| "Unable to parse retrieved public key")?;

    // Generate a wrapper key
    let mut wrapkey: [u8; 32] = [0; 32];
    sysrand
        .fill(&mut wrapkey)
        .with_context(|| "Unable to generate random wrapper key")?;
    let wrapkey = wrapkey;
    println!("Wrapper key sha256: {}", sha256_hex(&wrapkey));

    // Encrypt the wrapper key
    let wrapped_wrapkey = pubkey
        .encrypt(&mut rsarand, PaddingScheme::new_oaep::<Sha256>(), &wrapkey)
        .with_context(|| "Unable to encrypt wrapper key")?;

    // Encrypt the secret
    let wrapkey = aead::UnboundKey::new(&aead::AES_256_GCM, &wrapkey)
        .with_context(|| "Unable to generate UnboundKey")?;
    let mut wrapkey: aead::SealingKey<utils::CounterNonce> =
        aead::BoundKey::new(wrapkey, utils::CounterNonce::new());
    let aad = format!("{};{};{}", &secret_type, &secret_group, &secret_name);
    let aad = aead::Aad::from(&aad);
    wrapkey
        .seal_in_place_append_tag(aad, &mut secret)
        .with_context(|| "Unable to seal with generated wrapkey")?;

    // Store the secret finally
    proxy
        .store_secret(
            secret_type,
            secret_group,
            secret_name,
            wrapped_wrapkey,
            secret,
        )
        .with_context(|| format!("Failed to store secret {}", &secret_name))?;

    println!("Secret stored");

    Ok(())
}
