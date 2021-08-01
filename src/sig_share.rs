use crate::sig::Signature;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignatureShare(pub Signature);
