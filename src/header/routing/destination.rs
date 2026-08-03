
use crate::constants::{
    FINAL_NODE_META_INFO_LENGTH, MAX_PATH_LENGTH, SECURITY_PARAMETER, STREAM_CIPHER_OUTPUT_LENGTH,
};
use crate::crypto;
use crate::crypto::STREAM_CIPHER_INIT_VECTOR;
use crate::header::filler::{Filler, FILLER_STEP_SIZE_INCREASE};
use crate::header::keys::StreamCipherKey;
use crate::header::routing::nodes::EncryptedRoutingInformation;
use crate::header::routing::{RoutingFlag, Version, ENCRYPTED_ROUTING_INFO_SIZE, FINAL_HOP};
use crate::route::{Destination, DestinationAddressBytes, SURBIdentifier};
use crate::utils;
use rand::rng;

pub(super) struct FinalRoutingInformation {
    flag: RoutingFlag,
    version: Version,

    destination: DestinationAddressBytes,

    identifier: SURBIdentifier,
}

impl FinalRoutingInformation {
    
    pub fn new(dest: &Destination, route_len: usize, version: Version) -> Self { panic!("STUB: not implemented") }

    fn max_destination_length(route_len: usize) -> usize { panic!("STUB: not implemented") }

    fn max_padded_destination_identifier_length(route_len: usize) -> usize { panic!("STUB: not implemented") }

    pub(super) fn add_padding(self, route_len: usize) -> PaddedFinalRoutingInformation { panic!("STUB: not implemented") }
}

pub(super) struct PaddedFinalRoutingInformation {
    value: Vec<u8>,
}

impl PaddedFinalRoutingInformation {
    pub(super) fn encrypt(
        self,
        key: &StreamCipherKey,
        route_len: usize,
    ) -> EncryptedPaddedFinalRoutingInformation { panic!("STUB: not implemented") }
}

pub(super) struct EncryptedPaddedFinalRoutingInformation {
    value: Vec<u8>,
}

impl EncryptedPaddedFinalRoutingInformation {
    
    pub(super) fn combine_with_filler(
        self,
        filler: Filler,
        route_len: usize,
    ) -> EncryptedRoutingInformation { panic!("STUB: not implemented") }
}

#[cfg(test)]
mod test_encapsulating_final_routing_information_and_mac {
    use crate::header::mac::HeaderIntegrityMac;
    use crate::test_utils::fixtures::expanded_shared_secret_fixture;
    use crate::version::Version;
    use crate::{
        header::routing::EncapsulatedRoutingInformation,
        test_utils::{
            fixtures::{destination_fixture, filler_fixture},
            random_node,
        },
    };

    #[test]
    fn it_returns_mac_on_correct_data() {
        
        let route = [random_node(), random_node(), random_node()];
        let expanded_shared_secret = [
            expanded_shared_secret_fixture(),
            expanded_shared_secret_fixture(),
            expanded_shared_secret_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);
        let destination = destination_fixture();
        let final_routing_info = EncapsulatedRoutingInformation::for_final_hop(
            &destination,
            expanded_shared_secret.last().unwrap(),
            filler,
            route.len(),
            Version::default(),
        );

        let expected_mac = HeaderIntegrityMac::compute(
            expanded_shared_secret
                .last()
                .unwrap()
                .header_integrity_hmac_key(),
            final_routing_info.enc_routing_information.as_ref(),
        );
        assert_eq!(
            expected_mac.into_inner(),
            final_routing_info.integrity_mac.into_inner()
        );
    }
}

#[cfg(test)]
mod test_encapsulating_final_routing_information {
    use super::*;
    use crate::test_utils::fixtures::{
        destination_fixture, expanded_shared_secret_fixture, filler_fixture,
    };

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_and_flag_for_route_of_length_5(
    ) {
        let final_keys = expanded_shared_secret_fixture();
        let route_len = 5;
        let filler = filler_fixture(route_len - 1);
        let destination = destination_fixture();

        let final_routing_header =
            FinalRoutingInformation::new(&destination, route_len, Version::default())
                .add_padding(route_len)
                .encrypt(final_keys.stream_cipher_key(), route_len)
                .combine_with_filler(filler, route_len);

        let expected_final_header_len = ENCRYPTED_ROUTING_INFO_SIZE;

        assert_eq!(
            expected_final_header_len,
            final_routing_header.as_ref().len()
        );
    }

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_and_flag_for_route_of_length_3(
    ) {
        let final_keys = expanded_shared_secret_fixture();
        let route_len = 3;
        let filler = filler_fixture(route_len - 1);
        let destination = destination_fixture();

        let final_routing_header =
            FinalRoutingInformation::new(&destination, route_len, Version::default())
                .add_padding(route_len)
                .encrypt(final_keys.stream_cipher_key(), route_len)
                .combine_with_filler(filler, route_len);

        let expected_final_header_len = ENCRYPTED_ROUTING_INFO_SIZE;

        assert_eq!(
            expected_final_header_len,
            final_routing_header.as_ref().len()
        );
    }

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_and_flag_for_route_of_length_1(
    ) {
        let final_keys = expanded_shared_secret_fixture();
        let route_len = 1;
        let filler = filler_fixture(route_len - 1);
        let destination = destination_fixture();

        let final_routing_header =
            FinalRoutingInformation::new(&destination, route_len, Version::default())
                .add_padding(route_len)
                .encrypt(final_keys.stream_cipher_key(), route_len)
                .combine_with_filler(filler, route_len);

        let expected_final_header_len = ENCRYPTED_ROUTING_INFO_SIZE;

        assert_eq!(
            expected_final_header_len,
            final_routing_header.as_ref().len()
        );
    }

    #[test]
    #[should_panic]
    fn it_panics_if_it_receives_filler_different_than_filler_step_multiplied_with_i() {
        let final_keys = expanded_shared_secret_fixture();
        let route_len = 3;
        let filler = filler_fixture(route_len);
        let destination = destination_fixture();

        FinalRoutingInformation::new(&destination, route_len, Version::default())
            .add_padding(route_len)
            .encrypt(final_keys.stream_cipher_key(), route_len)
            .combine_with_filler(filler, route_len);
    }
}
