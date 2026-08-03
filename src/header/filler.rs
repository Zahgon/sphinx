
use crate::constants::{HEADER_INTEGRITY_MAC_SIZE, MAX_PATH_LENGTH, NODE_META_INFO_SIZE};
use crate::crypto;
use crate::header::shared_secret::ExpandedSharedSecret;
use crate::{constants, utils};

pub const FILLER_STEP_SIZE_INCREASE: usize = NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE;

#[derive(Debug, PartialEq, Eq)]
pub struct Filler(Vec<u8>);

impl Filler {
    pub(crate) fn new(expanded_shared_secrets: &[ExpandedSharedSecret]) -> Self { panic!("STUB: not implemented") }

    fn filler_step(
        mut filler_string_accumulator: Vec<u8>,
        i: usize,
        pseudorandom_bytes: Vec<u8>,
    ) -> Vec<u8> { panic!("STUB: not implemented") }
}

impl From<Vec<u8>> for Filler {
    fn from(raw_bytes: Vec<u8>) -> Self { panic!("STUB: not implemented") }
}

impl From<Filler> for Vec<u8> {
    fn from(filler: Filler) -> Self { panic!("STUB: not implemented") }
}

#[cfg(test)]
mod test_creating_pseudorandom_bytes {
    use super::*;
    use crate::header::shared_secret::ExpandSecret;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn with_no_keys_it_generates_empty_filler_string() {
        let expanded_shared_secret: Vec<_> = vec![];
        let filler_string = Filler::new(&expanded_shared_secret);

        assert_eq!(0, filler_string.0.len());
    }

    #[test]
    fn with_1_key_it_generates_filler_of_length_1_times_3_times_security_parameter() {
        let shared_keys = [PublicKey::from(&StaticSecret::random())];
        let expanded_shared_secret: Vec<_> = shared_keys
            .iter()
            .map(|&key| key.expand_shared_secret())
            .collect();
        let filler_string = Filler::new(&expanded_shared_secret);

        assert_eq!(FILLER_STEP_SIZE_INCREASE, filler_string.0.len());
    }

    #[test]
    fn with_3_key_it_generates_filler_of_length_3_times_3_times_security_parameter() {
        let shared_keys = [
            PublicKey::from(&StaticSecret::random()),
            PublicKey::from(&StaticSecret::random()),
            PublicKey::from(&StaticSecret::random()),
        ];
        let expanded_shared_secret: Vec<_> = shared_keys
            .iter()
            .map(|&key| key.expand_shared_secret())
            .collect();
        let filler_string = Filler::new(&expanded_shared_secret);
        assert_eq!(3 * FILLER_STEP_SIZE_INCREASE, filler_string.0.len());
    }

    #[test]
    #[should_panic]
    fn panics_with_more_keys_than_the_maximum_path_length() {
        let shared_keys: Vec<_> = std::iter::repeat_n((), constants::MAX_PATH_LENGTH + 1)
            .map(|_| PublicKey::from(&StaticSecret::random()))
            .collect();
        let expanded_shared_secrets: Vec<_> = shared_keys
            .iter()
            .map(|&key| key.expand_shared_secret())
            .collect();
        Filler::new(&expanded_shared_secrets);
    }
}

#[cfg(test)]
mod test_new_filler_bytes {
    use super::*;
    use crate::test_utils::fixtures::expanded_shared_secret_fixture;

    #[test]
    fn it_retusn_filler_bytes_of_correct_length_for_3_expanded_shared_secret() {
        let routing_key_1 = expanded_shared_secret_fixture();
        let routing_key_2 = expanded_shared_secret_fixture();
        let routing_key_3 = expanded_shared_secret_fixture();
        let expanded_shared_secret = [routing_key_1, routing_key_2, routing_key_3];
        let filler = Filler::new(&expanded_shared_secret);
        assert_eq!(
            FILLER_STEP_SIZE_INCREASE * (expanded_shared_secret.len()),
            filler.0.len()
        )
    }

    #[test]
    fn it_retusn_filler_bytes_of_correct_length_for_4_expanded_shared_secret() {
        let routing_key_1 = expanded_shared_secret_fixture();
        let routing_key_2 = expanded_shared_secret_fixture();
        let routing_key_3 = expanded_shared_secret_fixture();
        let routing_key_4 = expanded_shared_secret_fixture();
        let expanded_shared_secret = [routing_key_1, routing_key_2, routing_key_3, routing_key_4];
        let filler = Filler::new(&expanded_shared_secret);
        assert_eq!(
            FILLER_STEP_SIZE_INCREASE * (expanded_shared_secret.len()),
            filler.0.len()
        )
    }
}

#[cfg(test)]
mod test_generating_filler_bytes {
    use super::*;

    mod for_valid_inputs {
        use super::*;

        #[test]
        fn it_returns_the_xored_byte_vector_of_a_correct_length_for_i_1() {
            let pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
            let filler_string_accumulator = vec![];
            let filler_string =
                Filler::filler_step(filler_string_accumulator, 1, pseudorandom_bytes);
            assert_eq!(FILLER_STEP_SIZE_INCREASE, filler_string.len());
            for x in filler_string {
                assert_eq!(0, x); 
            }
        }

        #[test]
        fn it_returns_the_xored_byte_vector_of_a_correct_length_for_i_3() {
            let pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
            let filler_string_accumulator = vec![0u8; 2 * FILLER_STEP_SIZE_INCREASE];
            let filler_string =
                Filler::filler_step(filler_string_accumulator, 3, pseudorandom_bytes);
            assert_eq!(FILLER_STEP_SIZE_INCREASE * 3, filler_string.len());
            for x in filler_string {
                assert_eq!(0, x); 
            }
        }

        mod for_an_empty_filler_string_accumulator {
            use super::*;

            #[test]
            #[should_panic]
            fn it_panics() {
                let pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
                Filler::filler_step(vec![], 0, pseudorandom_bytes);
            }
        }
    }

    mod for_invalid_inputs {
        use super::*;

        #[test]
        #[should_panic]
        fn panics_for_incorrectly_sized_pseudorandom_bytes_vector_and_accumulator_vector() {
            let pseudorandom_bytes = vec![0; 1];
            Filler::filler_step(vec![], 0, pseudorandom_bytes);
        }

        #[test]
        #[should_panic]
        fn panics_with_incorrect_length_filler_accumulator() {
            let good_pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
            let wrong_accumulator = vec![0; 25];
            Filler::filler_step(wrong_accumulator, 1, good_pseudorandom_bytes);
        }
    }
}
