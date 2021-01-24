use delog::hex_str;
use pkcs11::types;
use pkcs11_uri::Pkcs11Uri;
use rsa::PublicKey;

fn main() {
    // let level = log::LevelFilter::Debug;
    let level = log::LevelFilter::Info;
    let _ = simplelog::SimpleLogger::init(level, simplelog::Config::default());
    if let Err(err) = try_main() {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&data);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    digest
}

fn try_main() -> anyhow::Result<()> {
    let uri_str = r"pkcs11:
        type=private;
        token=my-ca;
        object=my-signing-key
            ?pin-value=1234
            &module-path=/usr/lib/libsofthsm2.so";
    let uri = Pkcs11Uri::try_from(uri_str)?;
    let (context, session, object) = uri.identify_object().unwrap();

    //  CKM_SHA256_RSA_PKCS
    let mechanism = pkcs11::types::CK_MECHANISM {
        mechanism: pkcs11::types::CKM_SHA256_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    // now do a signature, assuming this is an RSA key
    context.sign_init(session, &mechanism, object).unwrap();
    let data = String::from("PKCS #11 is pretty horrible").into_bytes();
    let signature = context.sign(session, &data).unwrap();

    println!("signature: \n{}", hex_str!(signature.as_slice(), 32, sep: "\n"));
    assert_eq!(signature.len(), 256);

    let /*mut*/ n_buffer = [0u8; 256];  // rust-pkcs11 API is sloppy here; 256B = 2048b is enough for RSA2k keys
    let /*mut*/ e_buffer = [0u8; 3];    // always 0x10001 = u16::MAX + 2 anyway
    let mut n_attribute = types::CK_ATTRIBUTE::new(types::CKA_MODULUS);
    n_attribute.set_biginteger(&n_buffer);
    let mut e_attribute = types::CK_ATTRIBUTE::new(types::CKA_PUBLIC_EXPONENT);
    e_attribute.set_biginteger(&e_buffer);
    let mut template = vec![n_attribute, e_attribute];

    let (rv, attributes) = context.get_attribute_value(session, object, &mut template).unwrap();
    assert_eq!(rv, 0);
    let n = attributes[0].get_biginteger().unwrap();
    let e = attributes[1].get_biginteger().unwrap();
    dbg!(n.bits());
    dbg!(n.to_str_radix(10));
    assert_eq!(e.to_str_radix(10), "65537");

    // This be/le swap is due to a bug in `rust-pkcs11`:
    // https://github.com/mheese/rust-pkcs11/issues/44
    let n = rsa::BigUint::from_bytes_be(&n.to_bytes_le());
    let e = rsa::BigUint::from_bytes_be(&e.to_bytes_le());
    let public_key = rsa::RSAPublicKey::new(n, e).unwrap();

    let digest = sha256(&data);
    let padding_scheme = rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256));
    public_key.verify(padding_scheme, &digest, &signature).unwrap();

    Ok(())
}
