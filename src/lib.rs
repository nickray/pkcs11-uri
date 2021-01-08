//! PKCS#11 URI
//!
//! Bare bones implementation of the [RFC 7512][rfc-7512] URI scheme for locating keys and other PKCS#11 objects.
//!
//! This library is patched together from existing libraries, namely `pkcs11`, `uriparse` and `queryst`,
//! and is a work in progress.
//!
//! [rfc-7512]: https://tools.ietf.org/html/rfc7512

use core::convert::TryFrom;

pub type Session = pkcs11::types::CK_SESSION_HANDLE;
pub type Object =  pkcs11::types::CK_OBJECT_HANDLE;

#[cfg(test)]
mod tests;

use anyhow::anyhow;

pub fn locate(uri_str: &str) -> anyhow::Result<Object> {
    // let uri = "pkcs11:object=my-signing-key;type=private;serial=DECC0401648?pin-source=file:/etc/token";

    let uri = uriparse::URIReference::try_from(uri_str).unwrap();
    // dbg!(&uri);

    if uri.scheme() != Some(&uriparse::Scheme::PKCS11) {
        return Err(anyhow!("URI should have PKCS11 scheme"));
    }
    if uri.authority().is_some() {
        return Err(anyhow!("URI should not have an authority"));
    }

    if uri.path().segments().len() != 1 {
        return Err(anyhow!("URI should have exactly one segment"));
    }
    let segment = uri.path().segments()[0].as_str();
    // dbg!(segment);

    let attributes = queryst::parse(segment).unwrap();
    dbg!(attributes);

    let query_components = queryst::parse(uri.query().map(|query| query.as_str()).unwrap_or("")).unwrap();
    dbg!(query_components);

    todo!();
}

