
use crate::constants::VERSION_LENGTH;

pub const INITIAL_LEGACY_VERSION: Version = Version(1);
pub const UPDATED_LEGACY_VERSION: Version = Version(257);
pub const X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION: Version = Version(258);
pub const PAYLOAD_KEYS_SEEDS_VERSION: Version = Version(259);

pub const CURRENT_VERSION: Version = PAYLOAD_KEYS_SEEDS_VERSION;

pub const KNOWN_VERSIONS: &[Version] = &[
    INITIAL_LEGACY_VERSION,
    UPDATED_LEGACY_VERSION,
    X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION,
    PAYLOAD_KEYS_SEEDS_VERSION,
];

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Version(pub u16);

impl Version {
    pub fn new(value: u16) -> Version { panic!("STUB: not implemented") }

    pub fn value(&self) -> u16 { panic!("STUB: not implemented") }

    pub fn is_legacy(&self) -> bool { panic!("STUB: not implemented") }

    pub fn expects_legacy_full_payload_keys(&self) -> bool { panic!("STUB: not implemented") }

    pub fn from_bytes(bytes: [u8; VERSION_LENGTH]) -> Version { panic!("STUB: not implemented") }

    pub fn to_bytes(self) -> [u8; VERSION_LENGTH] { panic!("STUB: not implemented") }
}

impl Default for Version {
    fn default() -> Self { panic!("STUB: not implemented") }
}
