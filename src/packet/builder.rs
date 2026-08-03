use crate::version::Version;
use crate::{
    header::{delays::Delay, SphinxHeader},
    payload::Payload,
    route::{Destination, Node},
    Result, SphinxPacket,
};
use x25519_dalek::StaticSecret;

pub const DEFAULT_PAYLOAD_SIZE: usize = 1024;

pub struct SphinxPacketBuilder<'a> {
    payload_size: usize,
    initial_secret: Option<&'a StaticSecret>,
    version: Version,
}

impl<'a> SphinxPacketBuilder<'a> {
    pub fn new() -> Self { panic!("STUB: not implemented") }

    #[must_use]
    pub fn with_version(mut self, version: Version) -> Self { panic!("STUB: not implemented") }

    #[must_use]
    pub fn with_payload_size(mut self, payload_size: usize) -> Self { panic!("STUB: not implemented") }

    #[must_use]
    pub fn with_initial_secret(mut self, initial_secret: &'a StaticSecret) -> Self { panic!("STUB: not implemented") }

    pub fn build_packet<M: AsRef<[u8]>>(
        &self,
        message: M,
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
    ) -> Result<SphinxPacket> { panic!("STUB: not implemented") }
}

impl Default for SphinxPacketBuilder<'_> {
    fn default() -> Self { panic!("STUB: not implemented") }
}
