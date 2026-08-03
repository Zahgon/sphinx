
use crate::constants::INTEGRITY_MAC_KEY_SIZE;
use crate::crypto::STREAM_CIPHER_KEY_SIZE;
use crate::header::shared_secret::{expand_shared_secret, ExpandedSharedSecret};
use crate::route::Node;
use x25519_dalek::{PublicKey, StaticSecret};

pub type StreamCipherKey = [u8; STREAM_CIPHER_KEY_SIZE];
pub type HeaderIntegrityMacKey = [u8; INTEGRITY_MAC_KEY_SIZE];

pub struct KeyMaterial {
    pub initial_shared_secret: PublicKey,
    pub expanded_shared_secrets: Vec<ExpandedSharedSecret>,
}

impl KeyMaterial {
    
    pub fn derive(route: &[Node], initial_secret: &StaticSecret) -> Self { panic!("STUB: not implemented") }
}

#[cfg(test)]
mod deriving_key_material {
    use super::*;
    use crate::route::Node;

    #[cfg(test)]
    mod with_an_empty_route {
        use super::*;

        #[test]
        fn it_returns_no_routing_keys() {
            let empty_route: Vec<Node> = vec![];
            let initial_secret = StaticSecret::random();
            let key_material = KeyMaterial::derive(&empty_route, &initial_secret);
            assert_eq!(0, key_material.expanded_shared_secrets.len());
            assert_eq!(
                PublicKey::from(&initial_secret).as_bytes(),
                key_material.initial_shared_secret.as_bytes()
            )
        }
    }

    #[cfg(test)]
    mod for_a_route_with_3_forward_hops {
        use super::*;
        use crate::test_utils::random_node;

        fn setup() -> (Vec<Node>, StaticSecret, KeyMaterial) {
            let route: Vec<Node> = vec![random_node(), random_node(), random_node()];
            let initial_secret = StaticSecret::random();
            let key_material = KeyMaterial::derive(&route, &initial_secret);
            (route, initial_secret, key_material)
        }

        #[test]
        fn it_returns_number_of_shared_keys_equal_to_length_of_the_route() {
            let (_, _, key_material) = setup();
            assert_eq!(3, key_material.expanded_shared_secrets.len());
        }

        #[test]
        fn it_returns_correctly_inited_shared_secret() {
            let (_, initial_secret, key_material) = setup();
            assert_eq!(
                PublicKey::from(&initial_secret).as_bytes(),
                key_material.initial_shared_secret.as_bytes()
            );
        }

        #[test]
        fn it_generates_correct_expanded_shared_secret() {
            let (route, initial_secret, key_material) = setup();
            
            let mut expected_accumulator = vec![initial_secret];
            for (i, node) in route.iter().enumerate() {
                let expected_shared_key =
                    expected_accumulator
                        .iter()
                        .fold(node.pub_key, |acc, blinding_factor| {
                            PublicKey::from(blinding_factor.diffie_hellman(&acc).to_bytes())
                        });

                let expected_expanded_ss = expand_shared_secret(expected_shared_key.as_bytes());

                expected_accumulator.push(expected_expanded_ss.blinding_factor());
                assert_eq!(
                    expected_expanded_ss,
                    key_material.expanded_shared_secrets[i]
                )
            }
        }
    }
}
