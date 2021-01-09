use pkcs11_uri::Pkcs11Uri;

fn main() {
    if let Err(err) = try_main() {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}
fn try_main() -> anyhow::Result<()> {
    let uri_str = "pkcs11:library-version=3;token=The%20Software%20PKCS%2311%20Softtoken;id=%69%95%3E%5C%F4%BD%EC%91;object=my-signing-key;type=private;slot-id=327;serial=DECC0401648?pin-source=file:/etc/token";
    // let uri = "pkcs11:object=my-signing-key;type=private;serial=DECC0401648?pin-source=file:/etc/token&x=y";
    // let uri = "pkcs11:object=my-signing-key;type=private;serial=DECC0401648";
    // pkcs11_uri::identify(uri)?;
    let uri = Pkcs11Uri::try_parse(uri_str)?;
    dbg!(uri.clone());
    Ok(())
}
