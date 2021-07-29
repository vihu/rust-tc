use bls12_381::G2Affine;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature(pub G2Affine);
