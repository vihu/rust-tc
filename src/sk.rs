use crate::pk::PublicKey;
use crate::sig::Signature;
use crate::util::hash_g2;
use bls12_381::{G1Affine, G2Affine, Scalar};
use rand::distributions::Standard;
use rand::prelude::*;
use rand::{thread_rng, RngCore};
use std::fmt;

// TODO:
// - impl Drop for SecretKey
// - impl Zeroize for SecretKey

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SecretKey(Scalar);

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SecretKey({})", self.0)
    }
}

impl Distribution<SecretKey> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SecretKey {
        SecretKey::from_rng(rng)
    }
}

impl SecretKey {
    /// Use this!
    pub fn new() -> Self {
        let rng = thread_rng();
        SecretKey::random(rng)
    }

    pub fn default() -> Self {
        SecretKey::from_scalar(Scalar::zero())
    }

    pub fn from_rng<R: Rng + ?Sized>(rng: &mut R) -> Self {
        use ff::Field;
        SecretKey(Scalar::random(rng))
    }

    /// XXX: Don't use this
    pub fn from_raw(bytes: [u64; 4]) -> Self {
        SecretKey(Scalar::from_raw(bytes))
    }

    /// TODO: Remove unwrap and do something else?
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SecretKey(Scalar::from_bytes(bytes).unwrap())
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

    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> Signature {
        Signature(G2Affine::from(hash_g2(msg) * self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::SecretKey;
    use bls12_381::Scalar;
    use rand::distributions::Standard;
    use rand::{thread_rng, Rng};

    #[test]
    fn random() {
        let sk = SecretKey::new();
        assert_ne!(SecretKey::from_scalar(Scalar::zero()), sk);
        let pk = sk.public_key();
        let msg = b"Rip and tear, until it's done";
        let sig = sk.sign(msg);
        assert!(pk.verify(&sig, msg));
        // should not be able to verify other msg
        let other_msg = b"Other msg";
        assert_eq!(false, pk.verify(&sig, other_msg));
        // other signature cannot verify original msg
        let other_sig = sk.sign(other_msg);
        assert_eq!(false, pk.verify(&other_sig, msg));
    }

    #[test]
    fn default() {
        assert_eq!(SecretKey::from_scalar(Scalar::zero()), SecretKey::default())
    }

    #[test]
    fn std_dist() {
        let mut rng = thread_rng();
        let sk: SecretKey = rng.sample(Standard);
        let pk = sk.public_key();
        let msg = b"Rip and tear, until it's done";
        let sig = sk.sign(msg);
        assert!(pk.verify(&sig, msg));
    }
}
