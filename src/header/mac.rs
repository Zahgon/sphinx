
use crate::constants::{
    HeaderIntegrityHmacAlgorithm, HeaderIntegrityMacSize, HEADER_INTEGRITY_MAC_SIZE,
};
use crate::crypto;
use crate::header::keys::HeaderIntegrityMacKey;
use digest::array::Array;
use subtle::{Choice, ConstantTimeEq};

#[derive(Clone, Debug)]
pub struct HeaderIntegrityMac(Array<u8, HeaderIntegrityMacSize>);

impl HeaderIntegrityMac {
    pub(crate) fn compute(key: &HeaderIntegrityMacKey, header_data: &[u8]) -> Self { panic!("STUB: not implemented") }

    pub fn verify(
        &self,
        integrity_mac_key: &HeaderIntegrityMacKey,
        enc_routing_info: &[u8],
    ) -> bool { panic!("STUB: not implemented") }

    pub fn into_inner(self) -> Array<u8, HeaderIntegrityMacSize> { panic!("STUB: not implemented") }

    pub fn as_bytes(&self) -> &[u8] { panic!("STUB: not implemented") }

    pub fn from_bytes(bytes: [u8; HEADER_INTEGRITY_MAC_SIZE]) -> Self { panic!("STUB: not implemented") }
}

impl ConstantTimeEq for HeaderIntegrityMac {
    fn ct_eq(&self, other: &Self) -> Choice { panic!("STUB: not implemented") }
}

#[cfg(test)]
mod computing_integrity_mac {
    use super::*;
    use crate::constants::INTEGRITY_MAC_KEY_SIZE;
    use crate::header::routing::ENCRYPTED_ROUTING_INFO_SIZE;

    #[test]
    fn it_is_possible_to_verify_correct_mac() {
        let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let data = vec![3u8; ENCRYPTED_ROUTING_INFO_SIZE];
        let integrity_mac = HeaderIntegrityMac::compute(&key, &data);

        assert!(integrity_mac.verify(&key, &data));
    }

    #[test]
    fn it_lets_detecting_flipped_data_bits() {
        let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let mut data = vec![3u8; ENCRYPTED_ROUTING_INFO_SIZE];
        let integrity_mac = HeaderIntegrityMac::compute(&key, &data);
        data[10] = !data[10];
        assert!(!integrity_mac.verify(&key, &data));
    }
}
