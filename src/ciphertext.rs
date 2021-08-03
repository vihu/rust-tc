use crate::util;
use bls12_381::{pairing, G1Affine, G2Affine};

/// An encrypted message.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Ciphertext(pub G1Affine, pub Vec<u8>, pub G2Affine);

impl Ciphertext {
    /// Returns `true` if this is a valid ciphertext. This check is necessary to prevent
    /// chosen-ciphertext attacks.
    pub fn verify(&self) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *self;
        let hash = util::hash_g1_g2(*u, v);
        pairing(&G1Affine::generator(), w) == pairing(u, &hash)
    }
}
