use crate::util::{clear_scalar, hash_g2, xor_with_hash};
use crate::{Ciphertext, PublicKey, Signature};
use bls12_381::{G1Affine, G2Affine, Scalar};
use ff::Field;
use rand::distributions::Standard;
use rand::prelude::*;
use rand::{thread_rng, RngCore};
use std::fmt;
use zeroize::Zeroize;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SecretKey(pub Scalar); // XXX: Figure out how not to make Scalar pub

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SecretKey({})", self.0)
    }
}

impl Distribution<SecretKey> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SecretKey {
        SecretKey(Scalar::random(rng))
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        clear_scalar(&mut self.0)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SecretKey {
    pub fn from_mut(scalar: &mut Scalar) -> Self {
        let sk = SecretKey(*scalar);
        clear_scalar(scalar);
        sk
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> PublicKey {
        let g = G1Affine::generator();
        PublicKey(G1Affine::from(g * self.0))
    }

    /// Sign given msg using secret key
    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> Signature {
        Signature(G2Affine::from(hash_g2(msg) * self.0))
    }

    pub fn default() -> Self {
        SecretKey::from_scalar(Scalar::zero())
    }

    pub fn decrypt(&self, ct: &Ciphertext) -> Option<Vec<u8>> {
        if !ct.verify() {
            return None;
        }
        let Ciphertext(ref u, ref v, _) = *ct;
        let g = G1Affine::from(u * self.0);
        Some(xor_with_hash(g, v))
    }

    pub fn random() -> Self {
        rand::random()
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
    pub fn from_rngcore(rng: impl RngCore) -> Self {
        use ff::Field;
        SecretKey(Scalar::random(rng))
    }

    /// XXX: Don't use this too
    pub fn from_scalar(scalar: Scalar) -> Self {
        SecretKey(scalar)
    }
}

#[cfg(test)]
mod tests {
    use super::SecretKey;
    use bls12_381::Scalar;
    use rand::distributions::Standard;
    use rand::{thread_rng, Rng};
    use zeroize::Zeroize;

    #[test]
    fn random() {
        let sk = SecretKey::random();
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

    #[test]
    fn test_zeroize() {
        let zero_sk = SecretKey::from_mut(&mut Scalar::zero());

        let mut sk = SecretKey::random();
        assert_ne!(zero_sk, sk);

        sk.zeroize();
        assert_eq!(zero_sk, sk);
    }
}
