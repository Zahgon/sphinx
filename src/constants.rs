
use crate::crypto;
use digest::consts::U16;
use sha2::Sha256;

pub const SECURITY_PARAMETER: usize = 16; 
pub const MAX_PATH_LENGTH: usize = 5; 
pub const BLINDING_FACTOR_SIZE: usize = 2 * SECURITY_PARAMETER;

pub const REPLAY_TAG_SIZE: usize = 2 * SECURITY_PARAMETER;

pub const EXPANDED_SHARED_SECRET_LENGTH: usize = crypto::STREAM_CIPHER_KEY_SIZE
    + INTEGRITY_MAC_KEY_SIZE
    + PAYLOAD_KEY_SIZE
    + BLINDING_FACTOR_SIZE
    + REPLAY_TAG_SIZE;

pub const STREAM_CIPHER_OUTPUT_LENGTH: usize =
    (NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE) * (MAX_PATH_LENGTH + 1);
pub const DESTINATION_ADDRESS_LENGTH: usize = 2 * SECURITY_PARAMETER;
pub const NODE_ADDRESS_LENGTH: usize = 2 * SECURITY_PARAMETER;
pub const IDENTIFIER_LENGTH: usize = SECURITY_PARAMETER;
pub const INTEGRITY_MAC_KEY_SIZE: usize = SECURITY_PARAMETER;
pub const HEADER_INTEGRITY_MAC_SIZE: usize = SECURITY_PARAMETER;
pub const PAYLOAD_KEY_SEED_SIZE: usize = SECURITY_PARAMETER;
pub const PAYLOAD_KEY_SIZE: usize = 192; 
pub const DELAY_LENGTH: usize = 8; 
pub const NODE_META_INFO_SIZE: usize =
    NODE_ADDRESS_LENGTH + FLAG_LENGTH + DELAY_LENGTH + VERSION_LENGTH; 
pub const FINAL_NODE_META_INFO_LENGTH: usize =
    DESTINATION_ADDRESS_LENGTH + IDENTIFIER_LENGTH + FLAG_LENGTH + VERSION_LENGTH; 
pub const FLAG_LENGTH: usize = 1;
pub const PAYLOAD_SIZE: usize = 1024;
pub const VERSION_LENGTH: usize = 3; 
                                     
#[deprecated(note = "use EXPANDED_SHARED_SECRET_HKDF_INFO instead")]
pub const HKDF_INPUT_SEED: &[u8] = EXPANDED_SHARED_SECRET_HKDF_INFO;

pub const EXPANDED_SHARED_SECRET_HKDF_INFO: &[u8] =
    b"Dwste mou enan moxlo arketa makru kai ena upomoxlio gia na ton topothetisw kai tha kinisw thn gh.";

pub const EXPANDED_SHARED_SECRET_HKDF_SALT: &[u8] = b"";

pub const PAYLOAD_KEY_HKDF_INFO: &[u8] = b"sphinx-payload-key-V01-CS01-HKDF:SHA256-INFO";
pub const PAYLOAD_KEY_HKDF_SALT: &[u8] = b"sphinx-payload-key-V01-CS01-HKDF:SHA256-SALT";

pub type HeaderIntegrityMacSize = U16;

pub type HeaderIntegrityHmacAlgorithm = Sha256;

#[cfg(test)]
mod tests {
    use super::*;
    use digest::typenum::Unsigned;

    #[test]
    fn generic_type_sizes_are_consistent_with_defined_constants() {
        assert_eq!(
            HeaderIntegrityMacSize::to_usize(),
            HEADER_INTEGRITY_MAC_SIZE
        )
    }
}
