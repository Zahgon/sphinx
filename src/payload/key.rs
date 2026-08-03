
use crate::constants::{
    PAYLOAD_KEY_HKDF_INFO, PAYLOAD_KEY_HKDF_SALT, PAYLOAD_KEY_SEED_SIZE, PAYLOAD_KEY_SIZE,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::borrow::Borrow;

pub type PayloadKey = [u8; PAYLOAD_KEY_SIZE];
pub type PayloadKeySeed = [u8; PAYLOAD_KEY_SEED_SIZE];

pub fn derive_payload_key(seed: &[u8; PAYLOAD_KEY_SEED_SIZE]) -> PayloadKey { panic!("STUB: not implemented") }

pub trait SphinxPayloadKey<'a> {
    type Key: Borrow<PayloadKey>;

    fn payload_key(&'a self) -> Self::Key;
}

impl<'a> SphinxPayloadKey<'a> for &'a PayloadKey {
    type Key = &'a PayloadKey;

    fn payload_key(&self) -> Self::Key { panic!("STUB: not implemented") }
}

impl<'a> SphinxPayloadKey<'a> for PayloadKey {
    type Key = &'a PayloadKey;

    fn payload_key(&'a self) -> Self::Key { panic!("STUB: not implemented") }
}

impl SphinxPayloadKey<'_> for &PayloadKeySeed {
    type Key = PayloadKey;

    fn payload_key(&self) -> Self::Key { panic!("STUB: not implemented") }
}

impl SphinxPayloadKey<'_> for PayloadKeySeed {
    type Key = PayloadKey;

    fn payload_key(&self) -> Self::Key { panic!("STUB: not implemented") }
}
