use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::scalar::clamp_integer;
use curve25519_dalek::{MontgomeryPoint, Scalar};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519KeyPair {
    pub public_key: [u8; 32],
    pub private_seed: [u8; 32],
    pub comment: String,
}

impl Ed25519KeyPair {
    pub fn new() -> Self {
        let mut rng = StdRng::from_os_rng();

        let mut private_seed = [0u8; 32];
        rng.fill_bytes(&mut private_seed);
        private_seed = clamp_integer(private_seed);

        let secret_scalar = Scalar::from_bytes_mod_order(private_seed.clone());
        let public_key = X25519_BASEPOINT * secret_scalar;
        let public_key = public_key.to_bytes();

        Self {
            public_key,
            private_seed,
            comment: String::from(""),
        }
    }

    pub fn x25519(our_private: [u8; 32], their_public: [u8; 32]) -> [u8; 32] {
        let point = MontgomeryPoint(their_public);
        let secret = point.mul_clamped(our_private);
        secret.to_bytes()
    }
}
