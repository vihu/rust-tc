use crate::util;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective};
use group::Curve;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

/// An encrypted message.
#[derive(Eq, Debug, Clone)]
pub struct Ciphertext(pub G1Projective, pub Vec<u8>, pub G2Projective);

impl Ciphertext {
    /// Returns `true` if this is a valid ciphertext. This check is necessary to prevent
    /// chosen-ciphertext attacks.
    pub fn verify(&self) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *self;
        let hash = util::hash_g1_g2(*u, v);
        pairing(&G1Affine::generator(), &G2Affine::from(w))
            == pairing(&G1Affine::from(u), &G2Affine::from(hash))
    }
}

impl Hash for Ciphertext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let Ciphertext(ref u, ref v, ref w) = *self;
        u.to_affine().to_compressed().as_ref().hash(state);
        v.hash(state);
        w.to_affine().to_compressed().as_ref().hash(state);
    }
}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1 && self.2 == other.2
    }
}

impl PartialOrd for Ciphertext {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ciphertext {
    fn cmp(&self, other: &Self) -> Ordering {
        let Ciphertext(ref u0, ref v0, ref w0) = self;
        let Ciphertext(ref u1, ref v1, ref w1) = other;
        util::cmp_g1_projective(u0, u1)
            .then(v0.cmp(v1))
            .then(util::cmp_g2_projective(w0, w1))
    }
}
