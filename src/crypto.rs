use anyhow::{Context, Result};
use openssl::{
    rsa::RsaRef,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};

#[allow(unused)]
pub(crate) struct EncryptResult {
    pub wrapped_wrapkey: Vec<u8>,
    pub secret: Vec<u8>,
}

#[allow(unused)]
pub(crate) fn encrypt_secret<T>(
    public_key: &RsaRef<T>,
    secret_type: &str,
    secret_group: &str,
    secret_name: &str,
    secret_value: Vec<u8>,
) -> Result<EncryptResult>
where
    T: openssl::pkey::HasPublic,
{
    // Generate a wrapper key
    let mut wrapkey: [u8; 32] = [0; 32];
    openssl::rand::rand_bytes(&mut wrapkey).context("Unable to generate random wrapper key")?;
    let wrapkey = wrapkey;

    // Encrypt the wrapper key
    let mut wrapped_wrapkey = Vec::with_capacity(public_key.size() as usize);
    wrapped_wrapkey.resize(public_key.size() as usize, 0);
    public_key
        .public_encrypt(
            &wrapkey,
            &mut wrapped_wrapkey,
            openssl::rsa::Padding::PKCS1_OAEP,
        )
        .context("Unable to encrypt wrapper key")?;

    // Encrypt the secret
    let mut tag = vec![0; 16];
    let mut nonce = [0; 12];
    nonce[0] = 1;
    let aad = format!("{};{};{}", &secret_type, &secret_group, &secret_name);
    let mut secret = encrypt_aead(
        Cipher::aes_256_gcm(),
        &wrapkey,
        Some(&nonce),
        &aad.as_bytes(),
        &secret_value,
        &mut tag,
    )
    .context("Unable to encrypt secret")?;
    secret.extend_from_slice(&tag);

    Ok(EncryptResult {
        wrapped_wrapkey,
        secret,
    })
}

#[allow(unused)]
pub(crate) fn decrypt_secret(
    wrapkey: Vec<u8>,
    secret_type: &str,
    secret_group: &str,
    secret_name: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let aad = format!("{};{};{}", secret_type, secret_group, secret_name);

    let (value, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let mut nonce = [0; 12];
    nonce[0] = 1;

    decrypt_aead(
        Cipher::aes_256_gcm(),
        &wrapkey,
        Some(&nonce),
        aad.as_bytes(),
        value,
        &tag,
    )
    .context("Error decrypting secret")
    .map(|res| res.to_vec())
}

#[cfg(test)]
mod test {
    use openssl::{
        rand::rand_bytes,
        rsa::{Padding, Rsa},
    };

    #[test]
    fn test_encrypt_decrypt() {
        let privkey = Rsa::generate(2048).unwrap();
        let mut test_contents = vec![0; 128];

        // Generate random bytes to test with
        rand_bytes(&mut test_contents).unwrap();

        let encrypt_result = super::encrypt_secret(
            &privkey,
            "test_type",
            "test_group",
            "test_name",
            test_contents.clone(),
        )
        .unwrap();

        let mut decrypted_wrapkey = Vec::with_capacity(privkey.size() as usize);
        decrypted_wrapkey.resize(privkey.size() as usize, 0);
        let decrypted_wrapkey_size = privkey
            .private_decrypt(
                &encrypt_result.wrapped_wrapkey,
                &mut decrypted_wrapkey,
                Padding::PKCS1_OAEP,
            )
            .unwrap();
        decrypted_wrapkey.truncate(decrypted_wrapkey_size);

        let decrypted_contents = super::decrypt_secret(
            decrypted_wrapkey,
            "test_type",
            "test_group",
            "test_name",
            &encrypt_result.secret,
        )
        .unwrap();

        assert_eq!(test_contents, decrypted_contents);
    }
}
