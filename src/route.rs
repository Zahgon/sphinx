
use crate::constants::{DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH};
use crate::{Error, ErrorKind, Result};
use std::fmt::{self, Display, Formatter};

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash)]
pub struct DestinationAddressBytes([u8; DESTINATION_ADDRESS_LENGTH]);

impl DestinationAddressBytes {
    pub fn as_base58_string(&self) -> String { panic!("STUB: not implemented") }

    pub fn try_from_base58_string<S: Into<String>>(val: S) -> Result<Self> { panic!("STUB: not implemented") }

    pub fn from_bytes(b: [u8; DESTINATION_ADDRESS_LENGTH]) -> Self { panic!("STUB: not implemented") }

    pub fn try_from_byte_slice(b: &[u8]) -> Result<Self> { panic!("STUB: not implemented") }

    pub fn as_bytes_ref(&self) -> &[u8; DESTINATION_ADDRESS_LENGTH] { panic!("STUB: not implemented") }

    pub fn as_bytes(&self) -> [u8; DESTINATION_ADDRESS_LENGTH] { panic!("STUB: not implemented") }
}

impl Display for DestinationAddressBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { panic!("STUB: not implemented") }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash)]
pub struct NodeAddressBytes([u8; NODE_ADDRESS_LENGTH]);

impl NodeAddressBytes {
    pub fn as_base58_string(&self) -> String { panic!("STUB: not implemented") }

    pub fn try_from_base58_string<S: Into<String>>(val: S) -> Result<Self> { panic!("STUB: not implemented") }

    pub fn try_from_byte_slice(b: &[u8]) -> Result<Self> { panic!("STUB: not implemented") }

    pub fn from_bytes(b: [u8; NODE_ADDRESS_LENGTH]) -> Self { panic!("STUB: not implemented") }

    pub fn as_bytes(&self) -> &[u8; NODE_ADDRESS_LENGTH] { panic!("STUB: not implemented") }

    pub fn to_bytes(&self) -> [u8; NODE_ADDRESS_LENGTH] { panic!("STUB: not implemented") }
}

impl Display for NodeAddressBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { panic!("STUB: not implemented") }
}

pub type SURBIdentifier = [u8; IDENTIFIER_LENGTH];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    
    pub address: DestinationAddressBytes,
    pub identifier: SURBIdentifier,
}

impl Destination {
    pub fn new(address: DestinationAddressBytes, identifier: SURBIdentifier) -> Self { panic!("STUB: not implemented") }
}

#[derive(Clone, Debug)]
pub struct Node {
    pub address: NodeAddressBytes,
    pub pub_key: x25519_dalek::PublicKey,
}

impl Node {
    pub fn new(address: NodeAddressBytes, pub_key: x25519_dalek::PublicKey) -> Self { panic!("STUB: not implemented") }
}

#[cfg(test)]
mod address_encoding {
    use super::*;

    #[test]
    fn it_is_possible_to_encode_and_decode_address() {
        let dummy_address = NodeAddressBytes([42u8; 32]);
        let dummy_address_str = dummy_address.as_base58_string();
        let recovered = NodeAddressBytes::try_from_base58_string(dummy_address_str).unwrap();
        assert_eq!(dummy_address, recovered)
    }
}
