use crate::header::shared_secret::ExpandedSharedSecret;
use crate::version::Version;
use crate::{
    header::{self, delays::Delay, HEADER_SIZE},
    payload::{Payload, PAYLOAD_OVERHEAD_SIZE},
    route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes, SURBIdentifier},
    Error, ErrorKind, Result,
};
use builder::SphinxPacketBuilder;
use header::SphinxHeader;
use x25519_dalek::{PublicKey, StaticSecret};

pub mod builder;

pub struct ProcessedPacket {
    pub version: Version,
    pub data: ProcessedPacketData,
}

pub enum ProcessedPacketData {
    ForwardHop {
        next_hop_packet: SphinxPacket,
        next_hop_address: NodeAddressBytes,
        delay: Delay,
    },
    FinalHop {
        destination: DestinationAddressBytes,
        identifier: SURBIdentifier,
        payload: Payload,
    },
}

impl ProcessedPacket {
    pub fn shared_secret(&self) -> Option<PublicKey> { panic!("STUB: not implemented") }
}

pub struct SphinxPacket {
    pub header: SphinxHeader,
    pub payload: Payload,
}

#[allow(clippy::len_without_is_empty)]
impl SphinxPacket {
    
    pub fn new(
        message: Vec<u8>,
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
    ) -> Result<SphinxPacket> { panic!("STUB: not implemented") }

    pub fn shared_secret(&self) -> PublicKey { panic!("STUB: not implemented") }

    pub fn len(&self) -> usize { panic!("STUB: not implemented") }

    pub fn process_with_expanded_secret(
        self,
        expanded_shared_secret: &ExpandedSharedSecret,
    ) -> Result<ProcessedPacket> { panic!("STUB: not implemented") }

    pub fn process(self, node_secret_key: &StaticSecret) -> Result<ProcessedPacket> { panic!("STUB: not implemented") }

    pub fn to_bytes(&self) -> Vec<u8> { panic!("STUB: not implemented") }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> { panic!("STUB: not implemented") }
}

#[cfg(test)]
mod test_building_packet_from_bytes {
    use super::*;

    #[test]
    fn from_bytes_returns_error_if_bytes_are_too_short() {
        let bytes = [0u8; 1];
        let expected = ErrorKind::InvalidPacket;
        match SphinxPacket::from_bytes(&bytes) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when packet bytes too short"),
        };
    }
}
