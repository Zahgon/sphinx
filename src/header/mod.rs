
use crate::constants::HEADER_INTEGRITY_MAC_SIZE;
use crate::header::delays::Delay;
use crate::header::filler::Filler;
use crate::header::keys::KeyMaterial;
use crate::header::routing::{EncapsulatedRoutingInformation, ENCRYPTED_ROUTING_INFO_SIZE};
use crate::header::shared_secret::{ExpandSecret, ExpandedSharedSecret};
use crate::packet::ProcessedPacketData;
use crate::payload::key::{derive_payload_key, PayloadKey, PayloadKeySeed};
use crate::payload::Payload;
use crate::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes, SURBIdentifier};
use crate::version::Version;
use crate::{Error, ErrorKind, ProcessedPacket, Result, SphinxPacket};
use x25519_dalek::{PublicKey, StaticSecret};

pub mod delays;
pub mod filler;
pub mod keys;
pub mod mac;
pub mod routing;
pub mod shared_secret;

pub const HEADER_SIZE: usize = 32 + HEADER_INTEGRITY_MAC_SIZE + ENCRYPTED_ROUTING_INFO_SIZE;

#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub struct SphinxHeader {
    
    pub shared_secret: PublicKey,
    pub routing_info: Box<EncapsulatedRoutingInformation>,
}

pub struct ProcessedHeader {
    payload_key: PayloadKey,
    version: Version,
    data: ProcessedHeaderData,
}

pub enum ProcessedHeaderData {
    FinalHop {
        destination: DestinationAddressBytes,
        identifier: SURBIdentifier,
    },
    ForwardHop {
        updated_header: SphinxHeader,
        next_hop_address: NodeAddressBytes,
        delay: Delay,
    },
}

impl ProcessedHeader {
    pub(crate) fn payload_key(&self) -> &PayloadKey { panic!("STUB: not implemented") }

    pub(crate) fn attach_payload(self, payload: Payload) -> ProcessedPacket { panic!("STUB: not implemented") }
}

impl SphinxHeader {
    #[cfg(test)]
    pub(crate) fn new_current(
        initial_secret: &StaticSecret,
        route: &[Node],
        delays: &[Delay],
        destination: &Destination,
    ) -> BuiltHeader {
        let key_material = keys::KeyMaterial::derive(route, initial_secret);
        Self::build_header(
            key_material,
            route,
            delays,
            destination,
            crate::version::CURRENT_VERSION,
        )
    }

    pub(crate) fn new_versioned(
        initial_secret: &StaticSecret,
        route: &[Node],
        delays: &[Delay],
        destination: &Destination,
        version: Version,
    ) -> BuiltHeader { panic!("STUB: not implemented") }

    fn build_header(
        key_material: KeyMaterial,
        route: &[Node],
        delays: &[Delay],
        destination: &Destination,
        version: Version,
    ) -> BuiltHeader { panic!("STUB: not implemented") }

    #[allow(deprecated)]
    pub fn process_with_expanded_secret(
        self,
        expanded_secret: &ExpandedSharedSecret,
    ) -> Result<ProcessedHeader> { panic!("STUB: not implemented") }

    #[allow(deprecated)]
    pub fn process(self, node_secret_key: &StaticSecret) -> Result<ProcessedHeader> { panic!("STUB: not implemented") }

    pub fn compute_expanded_shared_secret(
        &self,
        node_secret_key: &StaticSecret,
    ) -> ExpandedSharedSecret { panic!("STUB: not implemented") }

    pub fn ensure_header_integrity(
        &self,
        expanded_shared_secret: &ExpandedSharedSecret,
    ) -> Result<()> { panic!("STUB: not implemented") }

    #[deprecated]
    pub fn unchecked_process_as_current(
        self,
        node_secret_key: &StaticSecret,
    ) -> Result<ProcessedHeader> { panic!("STUB: not implemented") }

    pub fn to_bytes(&self) -> Vec<u8> { panic!("STUB: not implemented") }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> { panic!("STUB: not implemented") }

    fn blind_the_shared_secret(
        shared_secret: PublicKey,
        blinding_factor: StaticSecret,
    ) -> PublicKey { panic!("STUB: not implemented") }
}

pub(crate) struct BuiltHeader {
    header: SphinxHeader,
    version: Version,
    expanded_secrets: Vec<ExpandedSharedSecret>,
}

impl BuiltHeader {
    fn new(
        version: Version,
        key_material: KeyMaterial,
        routing_information: EncapsulatedRoutingInformation,
    ) -> Self { panic!("STUB: not implemented") }

    pub(crate) fn derive_payload_keys(&self) -> Vec<PayloadKey> { panic!("STUB: not implemented") }

    pub(crate) fn legacy_full_payload_keys(&self) -> Vec<PayloadKey> { panic!("STUB: not implemented") }

    pub(crate) fn payload_key_seeds(&self) -> Vec<PayloadKeySeed> { panic!("STUB: not implemented") }

    pub(crate) fn into_header(self) -> SphinxHeader { panic!("STUB: not implemented") }
}

#[cfg(test)]
mod create_and_process_sphinx_packet_header {
    use super::*;
    use crate::{
        constants::NODE_ADDRESS_LENGTH,
        test_utils::fixtures::{destination_fixture, keygen},
    };
    use std::time::Duration;

    #[test]
    fn it_returns_correct_routing_information_at_each_hop_for_route_of_3_mixnodes() {
        let (node1_sk, node1_pk) = keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk, node2_pk) = keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk, node3_pk) = keygen();
        let node3 = Node {
            address: NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };
        let route = [node1, node2, node3];
        let route_destination = destination_fixture();
        let initial_secret = StaticSecret::random();
        let average_delay = 1;
        let delays =
            delays::generate_from_average_duration(route.len(), Duration::from_secs(average_delay));
        let sphinx_header =
            SphinxHeader::new_current(&initial_secret, &route, &delays, &route_destination)
                .into_header();

        let new_header = match sphinx_header.process(&node1_sk).unwrap().data {
            ProcessedHeaderData::ForwardHop {
                updated_header,
                next_hop_address,
                delay,
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                updated_header
            }
            _ => panic!(),
        };

        let new_header2 = match new_header.process(&node2_sk).unwrap().data {
            ProcessedHeaderData::ForwardHop {
                updated_header,
                next_hop_address,
                delay,
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                updated_header
            }
            _ => panic!(),
        };
        match new_header2.process(&node3_sk).unwrap().data {
            ProcessedHeaderData::FinalHop {
                destination,
                identifier: _,
            } => {
                assert_eq!(route_destination.address, destination);
            }
            _ => panic!(),
        };
    }
}

#[cfg(test)]
mod unwrap_routing_information {
    use crate::constants::{
        HEADER_INTEGRITY_MAC_SIZE, NODE_ADDRESS_LENGTH, NODE_META_INFO_SIZE,
        STREAM_CIPHER_OUTPUT_LENGTH,
    };
    use crate::crypto;
    use crate::header::routing::nodes::{
        EncryptedRoutingInformation, ParsedRawRoutingInformationData,
    };
    use crate::header::routing::{ENCRYPTED_ROUTING_INFO_SIZE, FORWARD_HOP};
    use crate::utils;

    #[test]
    fn it_returns_correct_unwrapped_routing_information() {
        let mut routing_info = [9u8; ENCRYPTED_ROUTING_INFO_SIZE];
        routing_info[0] = FORWARD_HOP;
        
        routing_info[1] = 0;

        let stream_cipher_key = [1u8; crypto::STREAM_CIPHER_KEY_SIZE];
        let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
            &stream_cipher_key,
            &crypto::STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );
        let encrypted_routing_info_vec = utils::bytes::xor(
            &routing_info,
            &pseudorandom_bytes[..ENCRYPTED_ROUTING_INFO_SIZE],
        );
        let mut encrypted_routing_info_array = [0u8; ENCRYPTED_ROUTING_INFO_SIZE];
        encrypted_routing_info_array.copy_from_slice(&encrypted_routing_info_vec);

        let enc_routing_info =
            EncryptedRoutingInformation::from_bytes(encrypted_routing_info_array);

        let expected_next_hop_encrypted_routing_information = [
            routing_info[NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE..].to_vec(),
            pseudorandom_bytes
                [NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE + ENCRYPTED_ROUTING_INFO_SIZE..]
                .to_vec(),
        ]
        .concat();
        let next_hop_encapsulated_routing_info =
            match enc_routing_info.unwrap(&stream_cipher_key).unwrap().data {
                ParsedRawRoutingInformationData::ForwardHop {
                    next_hop_address,
                    new_routing_information,
                    ..
                } => {
                    assert_eq!(
                        routing_info[2..2 + NODE_ADDRESS_LENGTH],
                        next_hop_address.to_bytes()
                    );
                    assert_eq!(
                        routing_info
                            [NODE_ADDRESS_LENGTH..NODE_ADDRESS_LENGTH + HEADER_INTEGRITY_MAC_SIZE]
                            .to_vec(),
                        new_routing_information.integrity_mac.as_bytes().to_vec()
                    );
                    new_routing_information
                }
                _ => panic!(),
            };

        let next_hop_encrypted_routing_information = next_hop_encapsulated_routing_info
            .enc_routing_information
            .as_ref();

        for i in 0..expected_next_hop_encrypted_routing_information.len() {
            assert_eq!(
                expected_next_hop_encrypted_routing_information[i],
                next_hop_encrypted_routing_information[i]
            );
        }
    }
}

#[cfg(test)]
mod unwrapping_using_previously_expanded_shared_secret {
    use super::*;
    use crate::constants::NODE_ADDRESS_LENGTH;
    use crate::test_utils::fixtures::{destination_fixture, keygen};
    use std::time::Duration;

    #[test]
    fn produces_same_result_for_forward_hop() {
        let (node1_sk, node1_pk) = keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (_, node2_pk) = keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let route = [node1, node2];
        let destination = destination_fixture();
        let initial_secret = StaticSecret::random();
        let average_delay = 1;
        let delays =
            delays::generate_from_average_duration(route.len(), Duration::from_secs(average_delay));
        let sphinx_header =
            SphinxHeader::new_current(&initial_secret, &route, &delays, &destination).into_header();
        let initial_secret = sphinx_header.shared_secret;

        let normally_unwrapped = match sphinx_header.clone().process(&node1_sk).unwrap().data {
            ProcessedHeaderData::ForwardHop { updated_header, .. } => updated_header,
            _ => unreachable!(),
        };

        let expanded_secret = node1_sk
            .diffie_hellman(&initial_secret)
            .expand_shared_secret();

        let derived_unwrapped = match sphinx_header
            .process_with_expanded_secret(&expanded_secret)
            .unwrap()
            .data
        {
            ProcessedHeaderData::ForwardHop { updated_header, .. } => updated_header,
            _ => unreachable!(),
        };

        assert_eq!(
            normally_unwrapped.shared_secret,
            derived_unwrapped.shared_secret
        );
        assert_eq!(
            normally_unwrapped.routing_info.to_bytes(),
            derived_unwrapped.routing_info.to_bytes()
        )
    }

    #[test]
    fn produces_same_result_for_final_hop() {
        let (node1_sk, node1_pk) = keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let route = [node1];
        let destination = destination_fixture();
        let initial_secret = StaticSecret::random();
        let average_delay = 1;
        let delays =
            delays::generate_from_average_duration(route.len(), Duration::from_secs(average_delay));
        let sphinx_header =
            SphinxHeader::new_current(&initial_secret, &route, &delays, &destination).into_header();
        let initial_secret = sphinx_header.shared_secret;

        let normally_unwrapped = sphinx_header.clone().process(&node1_sk).unwrap();
        let normally_unwrapped = match normally_unwrapped.data {
            ProcessedHeaderData::FinalHop {
                destination,
                identifier,
            } => (destination, identifier, normally_unwrapped.payload_key),
            _ => unreachable!(),
        };

        let expanded_secret = node1_sk
            .diffie_hellman(&initial_secret)
            .expand_shared_secret();

        let derived_unwrapped = sphinx_header
            .process_with_expanded_secret(&expanded_secret)
            .unwrap();

        let derived_unwrapped = match derived_unwrapped.data {
            ProcessedHeaderData::FinalHop {
                destination,
                identifier,
            } => (destination, identifier, derived_unwrapped.payload_key),
            _ => unreachable!(),
        };

        assert_eq!(normally_unwrapped.0, derived_unwrapped.0);
        assert_eq!(normally_unwrapped.1, derived_unwrapped.1);
        assert_eq!(normally_unwrapped.2.to_vec(), derived_unwrapped.2.to_vec())
    }
}

#[cfg(test)]
mod converting_header_to_bytes {
    use super::*;
    use crate::test_utils::fixtures::encapsulated_routing_information_fixture;

    #[test]
    fn it_is_possible_to_convert_back_and_forth() {
        let encapsulated_routing_info = Box::new(encapsulated_routing_information_fixture());
        let header = SphinxHeader {
            shared_secret: PublicKey::from(&StaticSecret::random()),
            routing_info: encapsulated_routing_info,
        };

        let header_bytes = header.to_bytes();
        let recovered_header = SphinxHeader::from_bytes(&header_bytes).unwrap();

        assert_eq!(
            header.shared_secret.as_bytes(),
            recovered_header.shared_secret.as_bytes()
        );
        assert_eq!(
            header.routing_info.to_bytes(),
            recovered_header.routing_info.to_bytes()
        );
    }
}
