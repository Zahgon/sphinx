
use crate::constants::SECURITY_PARAMETER;
use crate::payload::key::{PayloadKey, SphinxPayloadKey};
use crate::{Error, ErrorKind, Result};
use blake2::Blake2bMac;
use chacha20::ChaCha20;
use digest::consts::U32;
use digest::OutputSizeUser;
use lioness_rs::{KeyInit, Lioness};
use std::borrow::Borrow;

pub mod key;

type NymLionessDigest = Blake2bMac<U32>;
pub type NymLioness = Lioness<ChaCha20, NymLionessDigest>;

pub const PAYLOAD_OVERHEAD_SIZE: usize = SECURITY_PARAMETER + 1;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Payload(Vec<u8>);

#[allow(clippy::len_without_is_empty)]
impl Payload {
    
    pub fn encapsulate_message<K>(
        plaintext_message: &[u8],
        payload_keys: &[K],
        payload_size: usize,
    ) -> Result<Self>
    where
        K: for<'a> SphinxPayloadKey<'a>,
    { panic!("STUB: not implemented") }

    fn validate_parameters(payload_size: usize, plaintext_len: usize) -> Result<()> { panic!("STUB: not implemented") }

    fn set_final_payload(plaintext_message: &[u8], payload_size: usize) -> Self { panic!("STUB: not implemented") }

    fn add_encryption_layer<P: Borrow<PayloadKey>>(mut self, payload_key: P) -> Result<Self> { panic!("STUB: not implemented") }

    pub fn unwrap<P: Borrow<PayloadKey>>(mut self, payload_key: P) -> Result<Self> { panic!("STUB: not implemented") }

    fn find_start_of_padding(&self) -> Result<usize> { panic!("STUB: not implemented") }

    pub fn recover_plaintext(self) -> Result<Vec<u8>> { panic!("STUB: not implemented") }

    fn into_inner(self) -> Vec<u8> { panic!("STUB: not implemented") }

    fn inner(&self) -> &[u8] { panic!("STUB: not implemented") }

    pub fn len(&self) -> usize { panic!("STUB: not implemented") }

    pub fn as_bytes(&self) -> &[u8] { panic!("STUB: not implemented") }

    pub fn into_bytes(self) -> Vec<u8> { panic!("STUB: not implemented") }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> { panic!("STUB: not implemented") }
}

#[cfg(test)]
mod building_payload_from_bytes {
    use super::*;

    #[test]
    fn from_bytes_returns_error_if_bytes_are_too_short() {
        let bytes = [0u8; 1].to_vec();
        let expected = ErrorKind::InvalidPayload;
        match Payload::from_bytes(&bytes) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when packet bytes too short"),
        };
    }
}

#[cfg(test)]
mod parameter_verification {
    use super::*;

    #[test]
    fn it_returns_an_error_if_payload_size_is_smaller_than_the_overhead() {
        assert!(Payload::validate_parameters(PAYLOAD_OVERHEAD_SIZE - 1, 16).is_err());
    }

    #[test]
    fn it_returns_an_error_if_payload_size_is_smaller_than_the_lioness_blocklen() {
        assert!(Payload::validate_parameters(lioness::DIGEST_RESULT_SIZE - 1, 16).is_err());
    }

    #[test]
    fn it_returns_an_error_if_message_is_longer_than_maximum_allowed_length() {
        let payload_length = 100;
        let max_allowed_length = payload_length - PAYLOAD_OVERHEAD_SIZE;
        assert!(Payload::validate_parameters(payload_length, max_allowed_length + 1).is_err());
    }
}

#[cfg(test)]
mod final_payload_setting {
    use super::*;

    #[test]
    fn adds_correct_padding() {
        let plaintext_lengths = vec![0, 1, 16, 128, 4096];
        for plaintext_length in plaintext_lengths {
            
            let payload_size = plaintext_length + lioness::DIGEST_RESULT_SIZE;
            let final_payload =
                Payload::set_final_payload(&vec![42u8; plaintext_length], payload_size);
            let final_payload_inner = final_payload.into_inner();

            assert!(final_payload_inner
                .iter()
                .take(SECURITY_PARAMETER)
                .all(|&b| b == 0));
            
            assert!(final_payload_inner
                .iter()
                .skip(SECURITY_PARAMETER)
                .take(plaintext_length)
                .all(|&b| b == 42));
            
            assert_eq!(
                final_payload_inner[SECURITY_PARAMETER + plaintext_length],
                1
            );
            
            assert!(final_payload_inner
                .iter()
                .skip(SECURITY_PARAMETER + plaintext_length + 1)
                .all(|&b| b == 0))
        }
    }
}

#[cfg(test)]
mod test_encapsulating_payload {
    use super::*;
    use crate::constants::PAYLOAD_KEY_SIZE;

    #[test]
    fn works_with_single_encryption_layer() {
        let message = vec![1u8, 16];
        let payload_size = 512;
        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];

        assert!(Payload::encapsulate_message(&message, &[payload_key_1], payload_size).is_ok())
    }

    #[test]
    fn works_with_five_encryption_layers() {
        let message = vec![1u8, 16];
        let payload_size = 512;
        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_key_4 = [6u8; PAYLOAD_KEY_SIZE];
        let payload_key_5 = [7u8; PAYLOAD_KEY_SIZE];

        assert!(Payload::encapsulate_message(
            &message,
            &[
                payload_key_1,
                payload_key_2,
                payload_key_3,
                payload_key_4,
                payload_key_5
            ],
            payload_size
        )
        .is_ok())
    }
}

#[cfg(test)]
mod test_unwrapping_payload {
    use super::*;
    use crate::constants::{PAYLOAD_KEY_SIZE, SECURITY_PARAMETER};
    use crate::packet::builder::DEFAULT_PAYLOAD_SIZE;

    #[test]
    fn unwrapping_results_in_original_payload_plaintext() {
        let message = vec![42u8; 16];
        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, DEFAULT_PAYLOAD_SIZE).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key).unwrap()
            });

        let zero_bytes = vec![0u8; SECURITY_PARAMETER];
        let additional_padding =
            vec![0u8; DEFAULT_PAYLOAD_SIZE - PAYLOAD_OVERHEAD_SIZE - message.len()];
        let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
        assert_eq!(expected_payload, unwrapped_payload.into_inner());
    }
}

#[cfg(test)]
mod plaintext_recovery {
    use super::*;
    use crate::constants::PAYLOAD_KEY_SIZE;
    use crate::packet::builder::DEFAULT_PAYLOAD_SIZE;

    #[test]
    fn it_is_possible_to_recover_plaintext_from_valid_payload() {
        let message = vec![42u8; 160];

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, DEFAULT_PAYLOAD_SIZE).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key).unwrap()
            });

        let recovered_plaintext = unwrapped_payload.recover_plaintext().unwrap();

        assert_eq!(message, recovered_plaintext);
    }

    #[test]
    fn it_is_possible_to_recover_plaintext_even_if_is_just_ones() {
        let message = vec![1u8; 160];

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, DEFAULT_PAYLOAD_SIZE).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key).unwrap()
            });

        let recovered_plaintext = unwrapped_payload.recover_plaintext().unwrap();

        assert_eq!(message, recovered_plaintext);
    }

    #[test]
    fn it_is_possible_to_recover_plaintext_even_if_is_just_zeroes() {
        let message = vec![0u8; 160];

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, DEFAULT_PAYLOAD_SIZE).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key).unwrap()
            });

        let recovered_plaintext = unwrapped_payload.recover_plaintext().unwrap();

        assert_eq!(message, recovered_plaintext);
    }

    #[test]
    fn it_fails_to_recover_plaintext_from_invalid_payload() {
        let message = vec![42u8; 160];

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, DEFAULT_PAYLOAD_SIZE).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .skip(1) 
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key).unwrap()
            });

        assert!(unwrapped_payload.recover_plaintext().is_err())
    }

    #[test]
    fn it_fails_to_recover_plaintext_from_incorrectly_constructed_payload() {
        let zero_payload = Payload(vec![0u8; DEFAULT_PAYLOAD_SIZE]);

        assert!(zero_payload.recover_plaintext().is_err());
    }

    #[test]
    fn lioness_output_matches_legacy_dep() {
        let mut message = [69u8; 1000];
        let mut message2 = message;
        let key = [42u8; PAYLOAD_KEY_SIZE];

        let legacy_lioness =
            lioness::Lioness::<blake2_08::VarBlake2b, chacha_03::ChaCha>::new_raw(&key);
        legacy_lioness.encrypt(&mut message).unwrap();

        let lioness = NymLioness::new((&key).into());
        lioness.encrypt_block(&mut message2).unwrap();

        assert_eq!(message, message2);
    }
}
