use bls12_381::G1Affine;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DecryptionShare(pub G1Affine);
