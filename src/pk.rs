use crate::{sig::Signature, util::hash_g2};
use bls12_381::{pairing, G1Affine};

/// A public key.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PublicKey(pub G1Affine);

impl PublicKey {
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &Signature, msg: M) -> bool {
        let gt1 = pairing(&G1Affine::generator(), &sig.0);
        let gt2 = pairing(&self.0, &hash_g2(msg));
        gt1 == gt2
    }
}
