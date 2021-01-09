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

type StrPair<'a> = (&'a str, &'a str);

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
    ($Attributes:ident: $($attribute:ident($value:ty, $converter:tt) = $name:literal,)*) => {

        // #[derive(Copy, Clone, Debug, Deserialize, enum_iterator::IntoEnumIterator, PartialEq, Serialize)]
        #[derive(Clone, Debug, PartialEq)]
        pub enum $Attributes { $(
            $attribute($value),
        )* }

        impl<'a> TryFrom<(&'a str, &'a str)> for $Attributes {
            type Error = StrPair<'a>;
            fn try_from(pair: (&'a str, &'a str)) -> std::result::Result<Self, Self::Error> {
                use $Attributes::*;
                let (key, value) = pair;
                Ok(match (key, value) { $(
                    ($name, value) => $attribute($converter(value).or(Err(pair))?),
                        // Err(pair).with_context(|| Err(anyhow!("Value {} of attribute {} cannot be mapped", value, $name))))?),
                )*
                    _ => return Err(pair),
                })
            }
        }
    }
}


// #[derive(Copy, Clone, Debug, PartialEq)]
// pub struct SlotIdValue(usize);
// impl<'a> TryFrom<&'a str> for SlotIdValue {
//     type Error = &'a str;
//     fn try_from(s: &'a str) -> std::result::Result<Self, Self::Error> {
//         Ok(SlotIdValue(s.parse().or(Err(s))?))
//     }
// }

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

generate! { PathAttribute:
    Id(Vec<u8>, percent_decode_bytes) = "id",
    LibraryDescription(String, percent_decode_string) = "library-description",
    LibraryManufacturer(String, percent_decode_string) = "library-manufacturer",
    LibraryVersion(Version, parse_library_version) = "library-version",
    Manufacturer(String, percent_decode_string) = "manufacturer",
    Model(String, percent_decode_string) = "model",
    ObjectLabel(String, percent_decode_string) = "object",
    Serial([u8; 16], parse_serial_number) = "serial",
    SlotDescription(String, percent_decode_string) = "slot-description",
    SlotId(usize, parse_usize) = "slot-id",
    SlotManufacturer(String, percent_decode_string) = "slot-manufacturer",
    TokenLabel(String, percent_decode_string) = "token",
    Type(ObjectClass, parse_object_class) = "type",

    // TODO: vendor attributes
}

generate! { QueryAttribute:

    // should these be merged, and expect at most one of them?
    // NOTE: "the "pin-source" attribute value format and interpretation is left to be implementation specific"
    // However, the expectation is that it's
    // - either a file/https URI, or
    // - a specification how to call an external application (e.g., `|/usr/bin/echo $PIN` perhaps?)
    // I think it would be useful to support environment variables directly (e.g., `env:PIN`)
    PinSource(String, percent_decode_string) = "pin-source",
    PinValue(String, percent_decode_string) = "pin-value",

    // should these be merged, and expect at most one of them?
    ModuleName(String, percent_decode_string) = "module-name",
    ModulePath(String, percent_decode_string) = "module-path",

    // TODO: vendor attributes
}

/// Parsed [RFC 7512](https://tools.ietf.org/html/rfc7512) PKCS #11 URI
#[derive(Clone, Debug, PartialEq)]
pub struct Pkcs11Uri {
    pub path_attributes: Vec<PathAttribute>,
    pub query_attributes: Vec<QueryAttribute>,
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

        let mut path_attributes = Vec::<PathAttribute>::new();
        for (key, value) in segment.split(';').map(|component| {
            let tuple: Vec<&str> = component.splitn(2, '=').collect();
            let [key, value]: [&str; 2] = tuple.as_slice().try_into().unwrap();
            (key, value)
        }) {
            let attribute = PathAttribute::try_from((key, value)).unwrap();
            path_attributes.push(attribute);
        }

        // 3. parse Query Attributes
        let query = uri.query().map(|query| query.as_str()).unwrap_or("");

        let mut query_attributes: Vec<QueryAttribute> = Default::default();
        for (key, value) in query.split('&').map(|component| {
            let tuple: Vec<&str> = component.splitn(2, '=').collect();
            let [key, value]: [&str; 2] = tuple.as_slice().try_into().unwrap();
            (key, value)
        }) {
            let attribute = QueryAttribute::try_from((key, value)).unwrap();
            query_attributes.push(attribute);
        }

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

