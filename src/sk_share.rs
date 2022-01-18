use crate::{Ciphertext, DecryptionShare, PublicKeyShare, SecretKey, SignatureShare};
use bls12_381::{G1Affine, Scalar};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SecretKeyShare(SecretKey);

impl SecretKeyShare {
    pub fn from_sk(sk: SecretKey) -> Self {
        SecretKeyShare(sk)
    }

    pub fn new() -> Self {
        SecretKeyShare(SecretKey::random())
    }

    pub fn public_key_share(&self) -> PublicKeyShare {
        PublicKeyShare(self.0.public_key())
    }

    /// Signs the given message.
    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> SignatureShare {
        SignatureShare(self.0.sign(msg))
    }

    /// Returns a decryption share, or `None`, if the ciphertext isn't valid.
    pub fn decrypt_share(&self, ct: &Ciphertext) -> Option<DecryptionShare> {
        if !ct.verify() {
            return None;
        }
        Some(DecryptionShare(G1Affine::from(ct.0 * ((self.0).0))))
    }

    pub fn from_mut(scalar: &mut Scalar) -> Self {
        SecretKeyShare(SecretKey::from_mut(scalar))
    }
}

impl Default for SecretKeyShare {
    fn default() -> Self {
        Self::new()
    }
}
