use crate::util::hash_g1_g2;
use crate::{Ciphertext, DecryptionShare, PublicKey, SignatureShare};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKeyShare(pub PublicKey);

impl PublicKeyShare {
    pub fn verify_decryption_share(&self, share: &DecryptionShare, ct: &Ciphertext) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *ct;
        let hash = hash_g1_g2(*u, v);
        pairing(&G1Affine::from(share.0), &G2Affine::from(hash))
            == pairing(&G1Affine::from(self.0 .0), &G2Affine::from(w))
    }

    pub fn verify<M: AsRef<[u8]>>(&self, sig: &SignatureShare, msg: M) -> bool {
        self.0.verify(&sig.0, msg)
    }

    pub fn combine(&self, other: &PublicKeyShare) -> PublicKeyShare {
        PublicKeyShare(PublicKey((self.0).0 + G1Projective::from((other.0).0)))
    }
}
