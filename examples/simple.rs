fn main() {
    if let Err(err) = try_main() {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}
fn try_main() -> anyhow::Result<()> {
    let uri = "pkcs11:object=my-signing-key;type=private;serial=DECC0401648?pin-source=file:/etc/token";
    // let uri = "pkcs11:object=my-signing-key;type=private;serial=DECC0401648?pin-source=file:/etc/token&x=y";
    // let uri = "pkcs11:object=my-signing-key;type=private;serial=DECC0401648";
    pkcs11_uri::locate(uri)?;
    Ok(())
}
