
use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes128,
};
use digest::CtOutput;
use hmac::{EagerHash, Hmac, KeyInit, Mac};

pub use x25519_dalek::PublicKey;
pub type PrivateKey = x25519_dalek::StaticSecret;

pub const STREAM_CIPHER_KEY_SIZE: usize = 16;
pub const STREAM_CIPHER_INIT_VECTOR: [u8; 16] = [0u8; 16];

pub type HmacOutput<D> = CtOutput<Hmac<D>>;
type Aes128Ctr = ctr::Ctr64BE<Aes128>;

pub fn generate_pseudorandom_bytes(
    
    key: &[u8; STREAM_CIPHER_KEY_SIZE],
    iv: &[u8; STREAM_CIPHER_KEY_SIZE],
    length: usize,
) -> Vec<u8> { panic!("STUB: not implemented") }

pub fn compute_keyed_hmac<D>(key: &[u8], data: &[u8]) -> HmacOutput<D>
where
    D: EagerHash,
{ panic!("STUB: not implemented") }

#[cfg(test)]
mod generating_pseudorandom_bytes {
    use super::*;

    #[test]
    fn it_generates_output_of_size_10000() {
        let key: [u8; STREAM_CIPHER_KEY_SIZE] =
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let iv: [u8; STREAM_CIPHER_KEY_SIZE] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let rand_bytes = generate_pseudorandom_bytes(&key, &iv, 10000);
        assert_eq!(10000, rand_bytes.len());
    }
}
