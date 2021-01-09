//! PKCS#11 URI
//!
//! Bare bones implementation of the [RFC 7512][rfc-7512] URI scheme for locating keys and other PKCS#11 objects.
//!
//! This library is patched together from existing libraries, namely `pkcs11`, `uriparse` and
//! `percent-encoding`, and is a work in progress.
//!
//! [rfc-7512]: https://tools.ietf.org/html/rfc7512

// use core::convert::TryFrom;
// use core::convert::TryInto;
use core::convert::{TryFrom, TryInto};

pub type Session = pkcs11::types::CK_SESSION_HANDLE;
pub type Object =  pkcs11::types::CK_OBJECT_HANDLE;

#[cfg(test)]
mod tests;

use anyhow::anyhow;

fn parse_usize<'a>(value: &'a str) -> Result<usize, &'a str> {
    Ok(value.parse().or(Err(value))?)
}

fn percent_decode_string<'a>(value: &'a str) -> Result<String, &'a str> {
    Ok(percent_encoding::percent_decode_str(value).decode_utf8().or(Err(value))?.into_owned())
}

fn percent_decode_bytes<'a>(value: &'a str) -> Result<Vec<u8>, &'a str> {
    Ok(percent_encoding::percent_decode_str(value).collect())
}

fn parse_object_class<'a>(value: &'a str) -> Result<ObjectClass, &'a str> {
    Ok(value.try_into().or(Err(value))?)
}

fn parse_library_version<'a>(value: &'a str) -> Result<Version, &'a str> {
    Ok(if value.contains('.') {
        let tuple: Vec<&str> = value.splitn(2, '.').collect();
        let [major, minor]: [&str; 2] = tuple.as_slice().try_into().unwrap();
        let major = major.parse().or(Err(value))?;
        let minor = minor.parse().or(Err(value))?;
        Version { major, minor }
    } else {
        let major = value.parse().or(Err(value))?;
        Version { major, minor: 0 }
    })
}

// character-string serial number of the device. Must be padded with the blank character (' '). Should ''not'' be null-terminated.
// the definition of `CK_CHAR` is simply u8
//
// In rust-pkcs11, this is `pkcs11::types::padding::BlankPaddedString16`, even though the docs
// claim it's a UTF-8 string

fn parse_serial_number<'a>(value: &'a str) -> Result<[u8; 16], &'a str> {
    let mut characters: Vec<u8> = percent_encoding::percent_decode_str(value).collect();
    if characters.len() > 16 {
        return Err(value)
    } else {
        characters.resize(16, b' ');
        Ok(characters.try_into().unwrap())
    }
}

// The "library-version" attribute represents the major and minor
// version number of the library and its format is "M.N".  Both numbers
// are one byte in size; see the "libraryVersion" member of the CK_INFO
// structure in [PKCS11] for more information.  Value "M" for the
// attribute MUST be interpreted as "M" for the major and "0" for the
// minor version of the library.  If the attribute is present, the major
// version number is REQUIRED.  Both "M" and "N" MUST be decimal
// numbers.

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

macro_rules! generate {
    (($Attributes:ident, $delimiter:literal): $($attribute:ident($value:ty, $converter:tt) = $name:literal,)*) => {

        // #[derive(Copy, Clone, Debug, Deserialize, enum_iterator::IntoEnumIterator, PartialEq, Serialize)]
        #[derive(Clone, Debug, Default, PartialEq)]
        pub struct $Attributes { $(
            pub $attribute: Option<$value>,
        )* }

        impl<'a> TryFrom<&'a str> for $Attributes {
            type Error = &'a str;
            fn try_from(input: &'a str) -> std::result::Result<Self, Self::Error> {
                let mut attributes: $Attributes = Default::default();
                for component in input.split($delimiter) {
                    let tuple: Vec<&str> = component.splitn(2, '=').collect();
                    let [key, value]: [&str; 2] = tuple.as_slice().try_into().unwrap();
                    match key { $(
                        $name => {
                            let value: $value = $converter(value).or(Err(input))?;
                            if attributes.$attribute.is_some() {
                                return Err(input);
                            }
                            attributes.$attribute = Some(value);
                        }
                    )*
                        _ => return Err(key),
                    }
                }

                Ok(attributes)
            }
        }
    }
}

generate! { (PathAttributes, ';'):
    id(Vec<u8>, percent_decode_bytes) = "id",
    library_description(String, percent_decode_string) = "library-description",
    library_manufacturer(String, percent_decode_string) = "library-manufacturer",
    library_version(Version, parse_library_version) = "library-version",
    manufacturer(String, percent_decode_string) = "manufacturer",
    model(String, percent_decode_string) = "model",
    object_label(String, percent_decode_string) = "object",
    serial([u8; 16], parse_serial_number) = "serial",
    slot_description(String, percent_decode_string) = "slot-description",
    slot_id(usize, parse_usize) = "slot-id",
    slot_manufacturer(String, percent_decode_string) = "slot-manufacturer",
    token_label(String, percent_decode_string) = "token",
    object_class(ObjectClass, parse_object_class) = "type",

    // TODO: vendor attributes
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ObjectClass {
    Certificate,
    Data,
    PrivateKey,
    PublicKey,
    SecretKey,
}

impl<'a> TryFrom<&'a str> for ObjectClass {
    type Error = &'a str;
    fn try_from(s: &'a str) -> std::result::Result<Self, Self::Error> {
        use ObjectClass::*;
        Ok(match s {
            "cert" => Certificate,
            "data" => Data,
            "private" => PrivateKey,
            "public" => PublicKey,
            "secret-key" => SecretKey,
            _ => Err(s)?,
        })
    }
}

generate! { (QueryAttributes, '&'):

    // should these be merged, and expect at most one of them?
    // NOTE: "the "pin-source" attribute value format and interpretation is left to be implementation specific"
    // However, the expectation is that it's
    // - either a file/https URI, or
    // - a specification how to call an external application (e.g., `|/usr/bin/echo $PIN` perhaps?)
    // I think it would be useful to support environment variables directly (e.g., `env:PIN`)
    pin_source(String, percent_decode_string) = "pin-source",
    pin_value(String, percent_decode_string) = "pin-value",

    // should these be merged, and expect at most one of them?
    module_name(String, percent_decode_string) = "module-name",
    module_path(String, percent_decode_string) = "module-path",

    // TODO: vendor attributes
}

/// Parsed [RFC 7512](https://tools.ietf.org/html/rfc7512) PKCS #11 URI
#[derive(Clone, Debug, PartialEq)]
pub struct Pkcs11Uri {
    pub path_attributes: PathAttributes,
    pub query_attributes: QueryAttributes,
}

impl Pkcs11Uri {
    /// TryFrom as inherent method
    pub fn try_parse(uri_str: &str) -> anyhow::Result<Self> {
        Self::try_from(uri_str)
    }
}

impl<'a> TryFrom<&'a str> for Pkcs11Uri {
    type Error = anyhow::Error;

    fn try_from(uri_str: &'a str) -> std::result::Result<Self, Self::Error> {

        // 1. uriparse from string, check validity

        let uri = uriparse::URIReference::try_from(uri_str)?;
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

        // 2. parse Path Attributes
        let segment = uri.path().segments()[0].as_str();
        let path_attributes = PathAttributes::try_from(segment).unwrap();

        // 3. parse Query Attributes
        let query = uri.query().map(|query| query.as_str()).unwrap_or("");
        let query_attributes = QueryAttributes::try_from(query).unwrap();

        // 4. wrap up
        let parsed_uri = Pkcs11Uri { path_attributes, query_attributes };

        Ok(parsed_uri)
    }
}

pub fn identify(uri_str: &str) -> anyhow::Result<Vec<Object>> {
    // let uri_str = "pkcs11:object=my-signing-key;type=private;serial=DECC0401648?pin-source=file:/etc/token";
    let _uri = Pkcs11Uri::try_from(uri_str)?;

    todo!();
}

