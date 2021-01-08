use std::path::PathBuf;
use pkcs11::Ctx;
use serial_test::serial;

fn pkcs11_module_name() -> PathBuf {
    let path = std::env::var_os("PKCS11_MODULE").unwrap_or("/usr/lib/libsofthsm2.so".into());
    let path_buf = PathBuf::from(path);
    if !path_buf.exists() {
        panic!("Set location of PKCS#11 module with `PKCS11_MODULE` environment variable");
    }
    path_buf
}

#[test]
#[serial]
fn new_then_initialize() {
    let mut session = Ctx::new(pkcs11_module_name()).unwrap();
    let res = session.initialize(None);
    assert!(
        res.is_ok(),
        "failed to initialize session: {}",
        res.unwrap_err()
    );
    assert!(session.is_initialized(), "internal state is not initialized");
}

#[test]
#[serial]
fn new_and_initialize() {
    let result = Ctx::new_and_initialize(pkcs11_module_name());
    assert!(
        result.is_ok(),
        "failed to create or initialize new context: {}",
        result.unwrap_err()
    );
}
