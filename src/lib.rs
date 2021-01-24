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

use log::{debug, trace};
pub type Context = pkcs11::Ctx;
pub type SessionHandle = pkcs11::types::CK_SESSION_HANDLE;
pub type ObjectHandle = pkcs11::types::CK_OBJECT_HANDLE;
pub type SlotId = pkcs11::types::CK_SLOT_ID;

#[cfg(test)]
mod tests;

use anyhow::anyhow;

fn parse_slot_id(value: &str) -> Result<SlotId, &str> {
    Ok(value.parse().or(Err(value))?)
}

fn percent_decode_string(value: &str) -> Result<String, &str> {
    Ok(percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .or(Err(value))?
        .into_owned())
}

fn percent_decode_bytes(value: &str) -> Result<Vec<u8>, &str> {
    Ok(percent_encoding::percent_decode_str(value).collect())
}

fn parse_object_class(value: &str) -> Result<ObjectClass, &str> {
    Ok(value.try_into().or(Err(value))?)
}

fn parse_library_version(value: &str) -> Result<Version, &str> {
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

fn parse_serial_number(value: &str) -> Result<[u8; 16], &str> {
    let mut characters: Vec<u8> = percent_encoding::percent_decode_str(value).collect();
    if characters.len() > 16 {
        Err(value)
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
                            let value: $value = $converter(value).or(Err(component))?;
                            if attributes.$attribute.is_some() {
                                return Err(input);
                            }
                            attributes.$attribute = Some(value);
                        }
                    )*
                        _ => {
                            return Err(key);
                        }
                    }
                }

                Ok(attributes)
            }
        }
    }
}

generate! { (PathAttributes, ';'):
    library_description(String, percent_decode_string) = "library-description",
    library_manufacturer(String, percent_decode_string) = "library-manufacturer",
    library_version(Version, parse_library_version) = "library-version",

    slot_description(String, percent_decode_string) = "slot-description",
    slot_id(SlotId, parse_slot_id) = "slot-id",
    slot_manufacturer(String, percent_decode_string) = "slot-manufacturer",

    token_manufacturer(String, percent_decode_string) = "manufacturer",
    token_model(String, percent_decode_string) = "model",
    token_label(String, percent_decode_string) = "token",
    token_serial([u8; 16], parse_serial_number) = "serial",

    object_class(ObjectClass, parse_object_class) = "type",
    object_id(Vec<u8>, percent_decode_bytes) = "id",
    object_label(String, percent_decode_string) = "object",

    // TODO: vendor attributes
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ObjectClass {
    Certificate = 1,
    Data = 0,
    PrivateKey = 3,
    PublicKey = 2,
    SecretKey = 4,
    // OtpKey = 8,
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
            _ => return Err(s),
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
    raw_uri: String,
}

impl Pkcs11Uri {
    /// TryFrom as inherent method
    pub fn try_from(uri_str: &str) -> anyhow::Result<Self> {
        // 0. strip whitespace
        let uri_string: String = uri_str.chars().filter(|c| !c.is_whitespace()).collect();

        // 1. uriparse from string, check validity
        let uri = uriparse::URIReference::try_from(uri_string.as_str())?;
        // dbg!(&uri);

        // if uri.scheme() != Some(&uriparse::Scheme::PKCS11) {
        if uri.scheme() != Some(&uriparse::Scheme::PKCKS11) {
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
        debug!("segment: {}", segment);
        let path_attributes = PathAttributes::try_from(segment).unwrap();

        // 3. parse Query Attributes
        let query = uri.query().map(|query| query.as_str()).unwrap_or("");
        debug!("query: {}", query);
        let query_attributes = QueryAttributes::try_from(query).unwrap();

        // 4. wrap up
        let parsed_uri = Pkcs11Uri {
            path_attributes,
            query_attributes,
            raw_uri: uri_string,
        };

        Ok(parsed_uri)
    }
}

impl<'a> TryFrom<&'a str> for Pkcs11Uri {
    type Error = anyhow::Error;

    fn try_from(uri_str: &str) -> std::result::Result<Self, Self::Error> {
        Self::try_from(uri_str)
    }
}

pub fn split_once(s: &str, delimiter: char) -> Option<(&str, &str)> {
    let i = s.find(delimiter)?;
    Some((&s[..i], &s[i + 1..]))
}

impl Pkcs11Uri {
    fn matches_slot(&self, ctx: &pkcs11::Ctx, slot_id: pkcs11::types::CK_SLOT_ID) -> bool {
        // slot_id, slot_description, slot_manufacturer

        if self.path_attributes.slot_id == Some(slot_id) {
            return false;
        }
        let info = ctx.get_slot_info(slot_id).unwrap();
        trace!("{:?}", info);

        if let Some(slot_description) = &self.path_attributes.slot_description {
            if slot_description != String::from(info.slotDescription).as_str() {
                return false;
            }
        }
        if let Some(slot_manufacturer) = &self.path_attributes.slot_manufacturer {
            if slot_manufacturer != String::from(info.manufacturerID).as_str() {
                return false;
            }
        }
        true
    }

    fn matches_token(&self, ctx: &pkcs11::Ctx, slot_id: pkcs11::types::CK_SLOT_ID) -> bool {
        // slot_id, token_manufacturer, token_model, token_label

        if self.path_attributes.slot_id == Some(slot_id) {
            return false;
        }

        let info = ctx.get_token_info(slot_id).unwrap();
        trace!("{:?}", info);

        if let Some(token_manufacturer) = &self.path_attributes.token_manufacturer {
            if token_manufacturer != String::from(info.manufacturerID).as_str() {
                trace!("failed token_manufacturer check");
                return false;
            }
        }
        if let Some(token_model) = &self.path_attributes.token_model {
            if token_model != String::from(info.model).as_str() {
                trace!("failed token_model check");
                return false;
            }
        }
        if let Some(token_label) = &self.path_attributes.token_label {
            if token_label != String::from(info.label).as_str() {
                trace!("failed token_label check");
                return false;
            }
        }
        if let Some(token_serial) = &self.path_attributes.token_serial {
            if token_serial != &info.serialNumber.0 {
                trace!("failed token_serial check");
                return false;
            }
        }

        true
    }

    pub fn context(&self) -> Context {
        Context::new_and_initialize(self.query_attributes.module_path.as_ref().unwrap()).unwrap()
    }

    pub fn identify_slots(&self) -> anyhow::Result<Vec<SlotId>> {
        let ctx = self.context();

        let slots: Vec<SlotId> = ctx
            .get_slot_list(true)
            .unwrap()
            .iter()
            .copied()
            .filter(|slot| self.matches_slot(&ctx, *slot))
            .collect();

        Ok(slots)
    }

    pub fn identify_tokens(&self) -> anyhow::Result<Vec<SlotId>> {
        let ctx = self.context();

        let slots: Vec<SlotId> = ctx
            .get_slot_list(true)
            .unwrap()
            .iter()
            .copied()
            .filter(|slot| self.matches_slot(&ctx, *slot))
            .filter(|slot| self.matches_token(&ctx, *slot))
            .collect();

        Ok(slots)
    }

    pub fn identify_object(&self) -> anyhow::Result<(Context, SessionHandle, ObjectHandle)> {
        let ctx = self.context();

        // 1. find the slot
        let slots: Vec<SlotId> = ctx
            .get_slot_list(true)
            .unwrap()
            .iter()
            .copied()
            .filter(|slot| self.matches_slot(&ctx, *slot))
            .filter(|slot| self.matches_token(&ctx, *slot))
            .collect();

        debug!("slots: {:?}", slots);

        if slots.is_empty() {
            return Err(anyhow!("No slots found for URI `{}`", &self.raw_uri));
        }
        if slots.len() > 1 {
            return Err(anyhow!("Not implemented for multiple applicable slots"));
        }

        let slot = slots[0];

        // 2. create a logged-in session with the slot

        let flags = pkcs11::types::CKF_SERIAL_SESSION | pkcs11::types::CKF_RW_SESSION;
        let session = ctx
            .open_session(
                slot, flags, /*application: */ None, /*notify: */ None,
            )
            .unwrap();

        if let Some(pin) = self.query_attributes.pin_value.as_deref() {
            trace!("{:?}", pin);
            ctx.login(session, pkcs11::types::CKU_USER, Some(pin))
                .unwrap();
        } else if let Some(source) = self.query_attributes.pin_source.as_deref() {
            if let Some((scheme, content)) = split_once(source, ':') {
                match scheme {
                    "env" => {
                        let pin = std::env::var(content).unwrap();
                        trace!("{:?}", pin);
                        ctx.login(session, pkcs11::types::CKU_USER, Some(&pin))
                            .unwrap();
                    }
                    "file" => {
                        let pin = String::from_utf8_lossy(&std::fs::read(content).unwrap())
                            .trim()
                            .to_string();
                        trace!("{:?}", pin);
                        ctx.login(session, pkcs11::types::CKU_USER, Some(pin.as_str()))
                            .unwrap();
                    }
                    _ => {}
                }
            }
        } else {
            // no PIN = no login
            // ctx.login(session, pkcs11::types::CKU_USER, None).unwrap();
        }

        // 3. find the object
        // object_class: Option<ObjectClass>
        // object_id: Option<Vec<u8>>
        // object_label: Option<String>

        type Attribute = pkcs11::types::CK_ATTRIBUTE;
        let mut template = Vec::<Attribute>::new();
        if let Some(object_label) = &self.path_attributes.object_label {
            template.push(Attribute::new(pkcs11::types::CKA_LABEL).with_string(object_label));
        }
        if let Some(object_id) = &self.path_attributes.object_id {
            template.push(Attribute::new(pkcs11::types::CKA_ID).with_bytes(object_id.as_ref()));
        }
        if let Some(object_class) = &self.path_attributes.object_class {
            let raw_object_class = *object_class as u8 as _;
            template
                .push(Attribute::new(pkcs11::types::CKA_CLASS).with_ck_ulong(&raw_object_class));
        }

        ctx.find_objects_init(session, &template).unwrap();
        // ctx.find_objects_init(session, &[]).unwrap();
        let objects = ctx.find_objects(session, 10).unwrap();
        ctx.find_objects_final(session).unwrap();

        debug!("objects: {:?}", objects);

        if objects.is_empty() {
            return Err(anyhow!("No objects found for URI `{}`", &self.raw_uri));
        }
        if objects.len() > 1 {
            return Err(anyhow!("Not implemented for multiple applicable objects"));
        }

        let object = objects[0];
        Ok((ctx, session, object))
    }
}
