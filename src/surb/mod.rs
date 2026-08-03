use crate::constants::{NODE_ADDRESS_LENGTH, PAYLOAD_KEY_SEED_SIZE, PAYLOAD_KEY_SIZE};
use crate::header::delays::Delay;
use crate::payload::key::{PayloadKey, PayloadKeySeed};
use crate::payload::Payload;
use crate::route::{Destination, Node, NodeAddressBytes};
use crate::version::Version;
use crate::{header, SphinxPacket};
use crate::{Error, ErrorKind, Result};
use header::{SphinxHeader, HEADER_SIZE};
use std::fmt;
use x25519_dalek::StaticSecret;

#[derive(Debug)]
enum PayloadKeysMaterial {
    DerivedKeys(Vec<PayloadKey>),
    KeySeeds(Vec<PayloadKeySeed>),
}

impl PayloadKeysMaterial {
    fn from_bytes(bytes: &[u8]) -> Result<PayloadKeysMaterial> { panic!("STUB: not implemented") }
}

#[allow(non_snake_case)]
pub struct SURB {
    SURB_header: header::SphinxHeader,
    first_hop_address: NodeAddressBytes,
    payload_keys_material: PayloadKeysMaterial,
}

impl fmt::Debug for SURB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { panic!("STUB: not implemented") }
}

pub struct SURBMaterial {
    surb_route: Vec<Node>,
    surb_delays: Vec<Delay>,
    surb_destination: Destination,
    version: Version,
}

impl SURBMaterial {
    pub fn new(route: Vec<Node>, delays: Vec<Delay>, destination: Destination) -> Self { panic!("STUB: not implemented") }

    #[allow(non_snake_case)]
    pub fn construct_SURB(self) -> Result<SURB> { panic!("STUB: not implemented") }

    #[must_use]
    pub fn with_version(mut self, version: Version) -> Self { panic!("STUB: not implemented") }
}

#[allow(non_snake_case)]
impl SURB {
    pub fn new(surb_initial_secret: StaticSecret, surb_material: SURBMaterial) -> Result<Self> { panic!("STUB: not implemented") }

    pub fn use_surb(
        self,
        plaintext_message: &[u8],
        payload_size: usize,
    ) -> Result<(SphinxPacket, NodeAddressBytes)> { panic!("STUB: not implemented") }

    pub fn to_bytes(&self) -> Vec<u8> { panic!("STUB: not implemented") }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> { panic!("STUB: not implemented") }

    pub fn first_hop(&self) -> NodeAddressBytes { panic!("STUB: not implemented") }

    pub fn materials_count(&self) -> usize { panic!("STUB: not implemented") }

    pub fn uses_key_seeds(&self) -> bool { panic!("STUB: not implemented") }
}

#[cfg(test)]
mod prepare_and_use_process_surb {
    use super::*;
    use crate::constants::NODE_ADDRESS_LENGTH;
    use crate::header::{delays, HEADER_SIZE};
    use crate::version::{PAYLOAD_KEYS_SEEDS_VERSION, X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION};
    use crate::{
        packet::builder::DEFAULT_PAYLOAD_SIZE,
        test_utils::fixtures::{destination_fixture, keygen},
    };
    use std::time::Duration;

    fn surb_material_fixture() -> SURBMaterial {
        let (_, node1_pk) = keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (_, node2_pk) = keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (_, node3_pk) = keygen();
        let node3 = Node {
            address: NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = destination_fixture();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        SURBMaterial::new(surb_route, surb_delays, surb_destination)
    }

    #[allow(non_snake_case)]
    fn legacy_SURB_fixture() -> SURB {
        let surb_initial_secret = StaticSecret::random();
        let surb_material =
            surb_material_fixture().with_version(X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION);

        SURB::new(surb_initial_secret, surb_material).unwrap()
    }

    #[allow(non_snake_case)]
    fn seeded_SURB_fixture() -> SURB {
        let surb_initial_secret = StaticSecret::random();
        let surb_material = surb_material_fixture().with_version(PAYLOAD_KEYS_SEEDS_VERSION);

        SURB::new(surb_initial_secret, surb_material).unwrap()
    }

    #[test]
    fn returns_error_if_surb_route_empty() {
        let surb_route = Vec::new();
        let surb_destination = destination_fixture();
        let surb_initial_secret = StaticSecret::random();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));
        let expected = ErrorKind::InvalidSURB;

        match SURB::new(
            surb_initial_secret,
            SURBMaterial::new(surb_route, surb_delays, surb_destination),
        ) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when route empty"),
        };
    }

    #[test]
    fn surb_header_has_correct_length() {
        let pre_surb = legacy_SURB_fixture();
        assert_eq!(pre_surb.SURB_header.to_bytes().len(), HEADER_SIZE);
    }

    #[test]
    fn to_bytes_returns_correct_value() {
        let pre_surb = legacy_SURB_fixture();
        let PayloadKeysMaterial::DerivedKeys(keys) = &pre_surb.payload_keys_material else {
            unreachable!()
        };

        let pre_surb_bytes = pre_surb.to_bytes();
        let expected = [
            pre_surb.SURB_header.to_bytes(),
            [5u8; NODE_ADDRESS_LENGTH].to_vec(),
            keys[0].to_vec(),
            keys[1].to_vec(),
            keys[2].to_vec(),
        ]
        .concat();
        assert_eq!(pre_surb_bytes, expected);

        let pre_surb = seeded_SURB_fixture();
        let PayloadKeysMaterial::KeySeeds(seeds) = &pre_surb.payload_keys_material else {
            unreachable!()
        };

        let pre_surb_bytes = pre_surb.to_bytes();
        let expected = [
            pre_surb.SURB_header.to_bytes(),
            [5u8; NODE_ADDRESS_LENGTH].to_vec(),
            seeds[0].to_vec(),
            seeds[1].to_vec(),
            seeds[2].to_vec(),
        ]
        .concat();
        assert_eq!(pre_surb_bytes, expected);
    }

    #[test]
    fn returns_error_is_payload_too_large() {
        let pre_surb = legacy_SURB_fixture();
        let plaintext_message = vec![42u8; 5000];
        let expected = ErrorKind::InvalidPayload;

        match SURB::use_surb(pre_surb, &plaintext_message, DEFAULT_PAYLOAD_SIZE) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when payload bytes too long"),
        };
    }

    #[test]
    #[allow(non_snake_case)]
    fn can_be_converted_to_and_from_bytes_with_legacy_keys() {
        let dummy_SURB = legacy_SURB_fixture();
        let bytes = dummy_SURB.to_bytes();
        let recovered_SURB = SURB::from_bytes(&bytes).unwrap();

        assert_eq!(
            dummy_SURB.first_hop_address,
            recovered_SURB.first_hop_address
        );

        let PayloadKeysMaterial::DerivedKeys(original_keys) = &dummy_SURB.payload_keys_material
        else {
            unreachable!()
        };

        let PayloadKeysMaterial::DerivedKeys(recovered_keys) =
            &recovered_SURB.payload_keys_material
        else {
            unreachable!()
        };

        for i in 0..original_keys.len() {
            assert_eq!(original_keys[i], recovered_keys[i])
        }

        assert_eq!(
            dummy_SURB.SURB_header.to_bytes(),
            dummy_SURB.SURB_header.to_bytes()
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn can_be_converted_to_and_from_bytes_with_key_seeds() {
        let dummy_SURB = seeded_SURB_fixture();
        let bytes = dummy_SURB.to_bytes();
        let recovered_SURB = SURB::from_bytes(&bytes).unwrap();

        assert_eq!(
            dummy_SURB.first_hop_address,
            recovered_SURB.first_hop_address
        );

        let PayloadKeysMaterial::KeySeeds(original_seeds) = &dummy_SURB.payload_keys_material
        else {
            unreachable!()
        };

        let PayloadKeysMaterial::KeySeeds(recovered_seeds) = &recovered_SURB.payload_keys_material
        else {
            unreachable!()
        };

        for i in 0..original_seeds.len() {
            assert_eq!(original_seeds[i], recovered_seeds[i])
        }

        assert_eq!(
            dummy_SURB.SURB_header.to_bytes(),
            dummy_SURB.SURB_header.to_bytes()
        );
    }
}
