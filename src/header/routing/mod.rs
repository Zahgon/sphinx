
use crate::constants::{HEADER_INTEGRITY_MAC_SIZE, MAX_PATH_LENGTH, NODE_META_INFO_SIZE};
use crate::header::delays::Delay;
use crate::header::filler::Filler;
use crate::header::mac::HeaderIntegrityMac;
use crate::header::routing::destination::FinalRoutingInformation;
use crate::header::routing::nodes::{EncryptedRoutingInformation, RoutingInformation};
use crate::header::shared_secret::ExpandedSharedSecret;
use crate::route::{Destination, Node, NodeAddressBytes};
use crate::version::Version;
use crate::{Error, ErrorKind, Result};

pub const TRUNCATED_ROUTING_INFO_SIZE: usize =
    ENCRYPTED_ROUTING_INFO_SIZE - (NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE);
pub const ENCRYPTED_ROUTING_INFO_SIZE: usize =
    (NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE) * MAX_PATH_LENGTH;

pub mod destination;
pub mod nodes;

pub const FORWARD_HOP: RoutingFlag = 1;
pub const FINAL_HOP: RoutingFlag = 2;

pub type RoutingFlag = u8;

#[derive(Clone, Debug)]
pub struct EncapsulatedRoutingInformation {
    pub(crate) enc_routing_information: EncryptedRoutingInformation,
    pub(crate) integrity_mac: HeaderIntegrityMac,
}

impl EncapsulatedRoutingInformation {
    pub(crate) fn encapsulate(
        enc_routing_information: EncryptedRoutingInformation,
        integrity_mac: HeaderIntegrityMac,
    ) -> Self { panic!("STUB: not implemented") }

    pub(crate) fn new(
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
        expanded_shared_secrets: &[ExpandedSharedSecret],
        filler: Filler,
        version: Version,
    ) -> Self { panic!("STUB: not implemented") }

    fn for_final_hop(
        dest: &Destination,
        expanded_shared_secret: &ExpandedSharedSecret,
        filler: Filler,
        route_len: usize,
        version: Version,
    ) -> Self { panic!("STUB: not implemented") }

    fn for_forward_hops(
        encapsulated_destination_routing_info: Self,
        delays: &[Delay],
        route: &[Node], 
        expanded_shared_secrets: &[ExpandedSharedSecret], 
        version: Version,
    ) -> Self { panic!("STUB: not implemented") }

    pub fn to_bytes(&self) -> Vec<u8> { panic!("STUB: not implemented") }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> { panic!("STUB: not implemented") }
}

#[cfg(test)]
mod encapsulating_all_routing_information {
    use super::*;
    use crate::test_utils::{
        fixtures::{destination_fixture, expanded_shared_secret_fixture, filler_fixture},
        random_node,
    };

    #[test]
    #[should_panic]
    fn it_panics_if_route_is_longer_than_keys() {
        let route = [random_node(), random_node(), random_node()];
        let destination = destination_fixture();
        let delays = [
            Delay::new_from_nanos(10),
            Delay::new_from_nanos(20),
            Delay::new_from_nanos(30),
        ];
        let keys = [
            expanded_shared_secret_fixture(),
            expanded_shared_secret_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(
            &route,
            &destination,
            &delays,
            &keys,
            filler,
            Version::default(),
        );
    }

    #[test]
    #[should_panic]
    fn it_panics_if_keys_are_longer_than_route() {
        let route = [random_node(), random_node()];
        let destination = destination_fixture();
        let delays = [
            Delay::new_from_nanos(10),
            Delay::new_from_nanos(20),
            Delay::new_from_nanos(30),
        ];
        let keys = [
            expanded_shared_secret_fixture(),
            expanded_shared_secret_fixture(),
            expanded_shared_secret_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(
            &route,
            &destination,
            &delays,
            &keys,
            filler,
            Version::default(),
        );
    }

    #[test]
    #[should_panic]
    fn it_panics_if_empty_route_is_provided() {
        let route = vec![];
        let destination = destination_fixture();
        let delays = [
            Delay::new_from_nanos(10),
            Delay::new_from_nanos(20),
            Delay::new_from_nanos(30),
        ];
        let keys = [
            expanded_shared_secret_fixture(),
            expanded_shared_secret_fixture(),
            expanded_shared_secret_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(
            &route,
            &destination,
            &delays,
            &keys,
            filler,
            Version::default(),
        );
    }

    #[test]
    #[should_panic]
    fn it_panic_if_empty_keys_are_provided() {
        let route = [random_node(), random_node()];
        let destination = destination_fixture();
        let delays = [
            Delay::new_from_nanos(10),
            Delay::new_from_nanos(20),
            Delay::new_from_nanos(30),
        ];
        let keys = vec![];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(
            &route,
            &destination,
            &delays,
            &keys,
            filler,
            Version::default(),
        );
    }
}

#[cfg(test)]
mod encapsulating_forward_routing_information {
    use super::*;
    use crate::test_utils::{
        fixtures::{destination_fixture, expanded_shared_secret_fixture, filler_fixture},
        random_node,
    };

    #[test]
    fn it_correctly_generates_sphinx_routing_information_for_route_of_length_3() {
        
        let route = [random_node(), random_node(), random_node()];
        let destination = destination_fixture();
        let delay0 = Delay::new_from_nanos(10);
        let delay1 = Delay::new_from_nanos(20);
        let delay2 = Delay::new_from_nanos(30);
        let delays = [delay0, delay1, delay2].to_vec();
        let routing_keys = [
            expanded_shared_secret_fixture(),
            expanded_shared_secret_fixture(),
            expanded_shared_secret_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);
        let filler_copy = filler_fixture(route.len() - 1);
        assert_eq!(filler, filler_copy);

        let destination_routing_info = EncapsulatedRoutingInformation::for_final_hop(
            &destination,
            routing_keys.last().unwrap(),
            filler,
            route.len(),
            Version::default(),
        );

        let destination_routing_info_copy = destination_routing_info.clone();

        assert_eq!(
            destination_routing_info
                .enc_routing_information
                .as_ref()
                .to_vec(),
            destination_routing_info_copy
                .enc_routing_information
                .as_ref()
                .to_vec()
        );
        assert_eq!(
            destination_routing_info.integrity_mac.as_bytes().to_vec(),
            destination_routing_info_copy
                .integrity_mac
                .as_bytes()
                .to_vec()
        );

        let routing_info = EncapsulatedRoutingInformation::for_forward_hops(
            destination_routing_info,
            &delays,
            &route,
            &routing_keys,
            Version::default(),
        );

        let layer_1_routing = RoutingInformation::new(
            route[2].address,
            delay1,
            destination_routing_info_copy,
            Version::default(),
        )
        .encrypt(routing_keys[1].stream_cipher_key())
        .encapsulate_with_mac(routing_keys[1].header_integrity_hmac_key());

        let layer_0_routing = RoutingInformation::new(
            route[1].address,
            delay0,
            layer_1_routing,
            Version::default(),
        )
        .encrypt(routing_keys[0].stream_cipher_key())
        .encapsulate_with_mac(routing_keys[0].header_integrity_hmac_key());

        assert_eq!(
            routing_info.enc_routing_information.as_ref().to_vec(),
            layer_0_routing.enc_routing_information.as_ref().to_vec()
        );
        assert_eq!(
            routing_info.integrity_mac.into_inner(),
            layer_0_routing.integrity_mac.into_inner()
        );
    }
    #[test]
    fn it_correctly_generates_sphinx_routing_information_for_route_of_max_length() {
        
        assert_eq!(5, MAX_PATH_LENGTH); 

    }
}

#[cfg(test)]
mod converting_encapsulated_routing_info_to_bytes {
    use super::*;
    use crate::test_utils::fixtures::encapsulated_routing_information_fixture;

    #[test]
    fn it_is_possible_to_convert_back_and_forth() {
        let encapsulated_routing_info = encapsulated_routing_information_fixture();
        let encapsulated_routing_info_bytes = encapsulated_routing_info.to_bytes();

        let recovered_routing_info =
            EncapsulatedRoutingInformation::from_bytes(&encapsulated_routing_info_bytes).unwrap();
        assert_eq!(
            encapsulated_routing_info
                .enc_routing_information
                .as_ref()
                .to_vec(),
            recovered_routing_info
                .enc_routing_information
                .as_ref()
                .to_vec()
        );

        assert_eq!(
            encapsulated_routing_info.integrity_mac.into_inner(),
            recovered_routing_info.integrity_mac.into_inner()
        );
    }
}
