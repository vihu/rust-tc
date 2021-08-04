use bls12_381::G1Projective;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DecryptionShare(pub G1Projective);
