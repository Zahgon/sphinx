
use crate::constants::{
    DELAY_LENGTH, DESTINATION_ADDRESS_LENGTH, HEADER_INTEGRITY_MAC_SIZE, IDENTIFIER_LENGTH,
    NODE_ADDRESS_LENGTH, NODE_META_INFO_SIZE, STREAM_CIPHER_OUTPUT_LENGTH, VERSION_LENGTH,
};
use crate::crypto;
use crate::crypto::STREAM_CIPHER_INIT_VECTOR;
use crate::header::delays::Delay;
use crate::header::keys::{HeaderIntegrityMacKey, StreamCipherKey};
use crate::header::mac::HeaderIntegrityMac;
use crate::header::routing::{
    EncapsulatedRoutingInformation, RoutingFlag, ENCRYPTED_ROUTING_INFO_SIZE, FINAL_HOP,
    FORWARD_HOP, TRUNCATED_ROUTING_INFO_SIZE,
};
use crate::header::shared_secret::ExpandedSharedSecret;
use crate::header::{ProcessedHeader, ProcessedHeaderData, SphinxHeader};
use crate::payload::key::derive_payload_key;
use crate::route::{DestinationAddressBytes, NodeAddressBytes, SURBIdentifier};
use crate::utils;
use crate::version::Version;
use crate::{Error, ErrorKind, Result};
use std::fmt;
use x25519_dalek::PublicKey;

pub const PADDED_ENCRYPTED_ROUTING_INFO_SIZE: usize =
    ENCRYPTED_ROUTING_INFO_SIZE + NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE;

pub(super) struct RoutingInformation {
    flag: RoutingFlag,
    version: Version,
    
    node_address: NodeAddressBytes,
    delay: Delay,
    
    header_integrity_mac: HeaderIntegrityMac,
    
    next_routing_information: TruncatedRoutingInformation,
}

impl RoutingInformation {
    pub(super) fn new(
        node_address: NodeAddressBytes,
        delay: Delay,
        next_encapsulated_routing_information: EncapsulatedRoutingInformation,
        version: Version,
    ) -> Self { panic!("STUB: not implemented") }

    fn concatenate_components(self) -> Vec<u8> { panic!("STUB: not implemented") }

    pub(super) fn encrypt(self, key: &StreamCipherKey) -> EncryptedRoutingInformation { panic!("STUB: not implemented") }
}

#[derive(Clone)]
pub struct EncryptedRoutingInformation {
    value: [u8; ENCRYPTED_ROUTING_INFO_SIZE],
}

impl AsRef<[u8]> for EncryptedRoutingInformation {
    fn as_ref(&self) -> &[u8] { panic!("STUB: not implemented") }
}

impl fmt::Debug for EncryptedRoutingInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { panic!("STUB: not implemented") }
}

impl EncryptedRoutingInformation {
    pub fn from_bytes(bytes: [u8; ENCRYPTED_ROUTING_INFO_SIZE]) -> Self { panic!("STUB: not implemented") }

    fn truncate(self) -> TruncatedRoutingInformation { panic!("STUB: not implemented") }

    pub(super) fn encapsulate_with_mac(
        self,
        key: &HeaderIntegrityMacKey,
    ) -> EncapsulatedRoutingInformation { panic!("STUB: not implemented") }

    fn add_zero_padding(self) -> PaddedEncryptedRoutingInformation { panic!("STUB: not implemented") }

    pub(crate) fn unwrap(
        self,
        stream_cipher_key: &StreamCipherKey,
    ) -> Result<ParsedRawRoutingInformation> { panic!("STUB: not implemented") }
}

pub struct PaddedEncryptedRoutingInformation {
    value: Vec<u8>,
}

impl PaddedEncryptedRoutingInformation {
    pub fn decrypt(self, key: &StreamCipherKey) -> RawRoutingInformation { panic!("STUB: not implemented") }
}

pub struct RawRoutingInformation {
    value: Vec<u8>,
}

pub struct ParsedRawRoutingInformation {
    pub(crate) version: Version,
    pub(crate) data: ParsedRawRoutingInformationData,
}

pub enum ParsedRawRoutingInformationData {
    ForwardHop {
        next_hop_address: NodeAddressBytes,
        delay: Delay,
        new_routing_information: Box<EncapsulatedRoutingInformation>,
    },
    FinalHop {
        destination: DestinationAddressBytes,
        identifier: SURBIdentifier,
    },
}

impl ParsedRawRoutingInformation {
    pub(crate) fn into_processed_header(
        self,
        shared_secret: PublicKey,
        expanded_shared_secret: &ExpandedSharedSecret,
    ) -> ProcessedHeader { panic!("STUB: not implemented") }
}

impl RawRoutingInformation {
    pub(crate) fn parse(self) -> Result<ParsedRawRoutingInformation> { panic!("STUB: not implemented") }

    fn parse_as_forward_hop(self) -> ParsedRawRoutingInformation { panic!("STUB: not implemented") }

    fn parse_as_final_hop(self) -> ParsedRawRoutingInformation { panic!("STUB: not implemented") }
}

type TruncatedRoutingInformation = [u8; TRUNCATED_ROUTING_INFO_SIZE];

#[cfg(test)]
mod preparing_header_layer {
    use super::*;
    use crate::constants::HeaderIntegrityHmacAlgorithm;
    use crate::test_utils::fixtures::expanded_shared_secret_fixture;
    use crate::{
        constants::HEADER_INTEGRITY_MAC_SIZE,
        test_utils::fixtures::{encapsulated_routing_information_fixture, node_address_fixture},
    };

    #[test]
    fn it_returns_encrypted_truncated_address_and_flag_concatenated_with_inner_layer_and_mac_on_it()
    {
        let node_address = node_address_fixture();
        let delay = Delay::new_from_nanos(10);
        let previous_node_routing_keys = expanded_shared_secret_fixture();
        let inner_layer_routing = encapsulated_routing_information_fixture();

        let version = Version::default();
        
        let concatenated_materials: Vec<u8> = [
            vec![FORWARD_HOP],
            version.to_bytes().to_vec(),
            node_address.to_bytes().to_vec(),
            delay.to_bytes().to_vec(),
            inner_layer_routing.integrity_mac.as_bytes().to_vec(),
            inner_layer_routing
                .enc_routing_information
                .value
                .to_vec()
                .iter()
                .cloned()
                .take(TRUNCATED_ROUTING_INFO_SIZE)
                .collect(),
        ]
        .concat();

        let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
            previous_node_routing_keys.stream_cipher_key(),
            &STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );

        let expected_encrypted_routing_info_vec = utils::bytes::xor(
            &concatenated_materials,
            &pseudorandom_bytes[..ENCRYPTED_ROUTING_INFO_SIZE],
        );

        let expected_routing_mac = crypto::compute_keyed_hmac::<HeaderIntegrityHmacAlgorithm>(
            previous_node_routing_keys.header_integrity_hmac_key(),
            &expected_encrypted_routing_info_vec,
        );
        let mut expected_routing_mac = expected_routing_mac.into_bytes().to_vec();
        expected_routing_mac.truncate(HEADER_INTEGRITY_MAC_SIZE);

        let next_layer_routing =
            RoutingInformation::new(node_address, delay, inner_layer_routing, Version::default())
                .encrypt(previous_node_routing_keys.stream_cipher_key())
                .encapsulate_with_mac(previous_node_routing_keys.header_integrity_hmac_key());

        assert_eq!(
            expected_encrypted_routing_info_vec,
            next_layer_routing.enc_routing_information.value.to_vec()
        );
        assert_eq!(
            expected_routing_mac,
            next_layer_routing.integrity_mac.as_bytes().to_vec()
        );
    }
}

#[cfg(test)]
mod encrypting_routing_information {
    use super::*;
    use crate::{
        crypto::STREAM_CIPHER_KEY_SIZE,
        test_utils::fixtures::{header_integrity_mac_fixture, node_address_fixture},
    };

    #[test]
    fn it_is_possible_to_decrypt_it_to_recover_original_data() {
        let key = [2u8; STREAM_CIPHER_KEY_SIZE];
        let flag = FORWARD_HOP;
        let address = node_address_fixture();
        let delay = Delay::new_from_nanos(15);
        let mac = header_integrity_mac_fixture();
        let next_routing = [8u8; TRUNCATED_ROUTING_INFO_SIZE];

        let version = Version::default();
        let encryption_data = [
            vec![flag],
            version.to_bytes().to_vec(),
            address.to_bytes().to_vec(),
            delay.to_bytes().to_vec(),
            mac.as_bytes().to_vec(),
            next_routing.to_vec(),
        ]
        .concat();

        let routing_information = RoutingInformation {
            flag: FORWARD_HOP,
            version,
            node_address: address,
            delay,
            header_integrity_mac: mac,
            next_routing_information: next_routing,
        };

        let encrypted_data = routing_information.encrypt(&key);
        let decryption_key_source = crypto::generate_pseudorandom_bytes(
            &key,
            &STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );
        let decryption_key = &decryption_key_source[..ENCRYPTED_ROUTING_INFO_SIZE];
        let decrypted_data = utils::bytes::xor(&encrypted_data.value, decryption_key);
        assert_eq!(encryption_data, decrypted_data);
    }
}

#[cfg(test)]
mod truncating_routing_information {
    use crate::test_utils::fixtures::encrypted_routing_information_fixture;

    #[test]
    fn it_does_not_change_prefixed_data() {
        let encrypted_routing_info = encrypted_routing_information_fixture();
        let routing_info_data_copy = encrypted_routing_info.value;

        let truncated_routing_info = encrypted_routing_info.truncate();
        for i in 0..truncated_routing_info.len() {
            assert_eq!(truncated_routing_info[i], routing_info_data_copy[i]);
        }
    }
}

#[cfg(test)]
mod parse_decrypted_routing_information {
    use super::*;
    use crate::{
        header::routing::ENCRYPTED_ROUTING_INFO_SIZE,
        test_utils::fixtures::{header_integrity_mac_fixture, node_address_fixture},
    };

    #[test]
    fn it_returns_next_hop_address_integrity_mac_enc_routing_info() {
        let flag = FORWARD_HOP;
        let address_fixture = node_address_fixture();
        let delay = Delay::new_from_nanos(10);
        let integrity_mac = header_integrity_mac_fixture();
        let next_routing_information = [1u8; ENCRYPTED_ROUTING_INFO_SIZE];
        let version = Version::default();

        let data = [
            vec![flag],
            version.to_bytes().to_vec(),
            address_fixture.to_bytes().to_vec(),
            delay.to_bytes().to_vec(),
            integrity_mac.as_bytes().to_vec(),
            next_routing_information.to_vec(),
        ]
        .concat();

        let raw_routing_info = RawRoutingInformation { value: data };

        let parsed = raw_routing_info.parse().unwrap();
        match parsed.data {
            ParsedRawRoutingInformationData::ForwardHop {
                next_hop_address,
                delay: _,
                new_routing_information,
            } => {
                assert_eq!(address_fixture, next_hop_address);
                assert_eq!(
                    integrity_mac.as_bytes().to_vec(),
                    new_routing_information.integrity_mac.as_bytes().to_vec()
                );
                assert_eq!(
                    next_routing_information.to_vec(),
                    new_routing_information
                        .enc_routing_information
                        .as_ref()
                        .to_vec()
                );
            }
            ParsedRawRoutingInformationData::FinalHop { .. } => panic!(),
        }
    }
}
