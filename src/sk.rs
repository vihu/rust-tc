use crate::pk::PublicKey;
use crate::sig::Signature;
use crate::util::hash_g2;
use bls12_381::{G1Affine, G2Affine, Scalar};
use rand::{thread_rng, RngCore};

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SecretKey(Scalar);

impl SecretKey {
    /// Use this!
    pub fn generate() -> Self {
        let rng = thread_rng();
        SecretKey::random(rng)
    }

    /// XXX: Don't use this
    pub fn from_raw(bytes: [u64; 4]) -> Self {
        SecretKey(Scalar::from_raw(bytes))
    }

    /// XXX: Don't use this either
    pub fn random(rng: impl RngCore) -> Self {
        use ff::Field;
        SecretKey(Scalar::random(rng))
    }

    /// XXX: Don't use this too
    pub fn from_scalar(scalar: Scalar) -> Self {
        SecretKey(scalar)
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> PublicKey {
        let g = G1Affine::generator();
        PublicKey(G1Affine::from(g * self.0))
    }

    pub fn sign_g2<H: Into<G2Affine>>(&self, hash: H) -> Signature {
        Signature(G2Affine::from(hash.into() * self.0))
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.sign_g2(hash_g2(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::SecretKey;
    use bls12_381::Scalar;

    #[test]
    fn test_random() {
        let sk = SecretKey::generate();
        assert_ne!(SecretKey::from_scalar(Scalar::zero()), sk);
        let pk = sk.public_key();
        let msg = b"Rip and tear, until it's done";
        let sig = sk.sign(msg);
        assert!(pk.verify(&sig, msg))
    }
}
