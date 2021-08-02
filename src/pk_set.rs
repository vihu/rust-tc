use crate::ciphertext::Ciphertext;
use crate::commitment::Commitment;
use crate::dec_share::DecryptionShare;
use crate::into_scalar::IntoScalar;
use crate::pk::PublicKey;
use crate::pk_share::PublicKeyShare;
use crate::sig::Signature;
use crate::sig_share::SignatureShare;
use crate::util::*;
use anyhow::{anyhow, bail, Result};
use bls12_381::{G1Affine, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::prime::PrimeCurve;
use std::borrow::Borrow;
use std::hash::{Hash, Hasher};

/// A public key and an associated set of public key shares.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct PublicKeySet {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    pub commit: Commitment,
}

impl Hash for PublicKeySet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.commit.hash(state);
    }
}

impl From<Commitment> for PublicKeySet {
    fn from(commit: Commitment) -> PublicKeySet {
        PublicKeySet { commit }
    }
}

impl PublicKeySet {
    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.commit.degree()
    }

    /// Returns the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.commit.coeff[0])
    }

    /// Returns the `i`-th public key share.
    pub fn public_key_share<T: IntoScalar>(&self, i: T) -> PublicKeyShare {
        let value = self.commit.evaluate(into_scalar_plus_1(i));
        PublicKeyShare(PublicKey(value))
    }

    // pub fn combine_signatures<'a, T, I>(&self, shares: I) -> Result<Signature>
    // where
    //     I: IntoIterator<Item = (T, &'a SignatureShare)>,
    //     T: IntoScalar,
    // {
    //     let samples = shares.into_iter().map(|(i, share)| (i, &(share.0).0));
    //     Ok(Signature(interpolate_g2(self.commit.degree(), samples)?))
    // }

    // /// Combines the shares to decrypt the ciphertext.
    // pub fn decrypt<'a, T, I>(&self, shares: I, ct: &Ciphertext) -> Result<Vec<u8>>
    // where
    //     I: IntoIterator<Item = (T, &'a DecryptionShare)>,
    //     T: IntoScalar,
    // {
    //     let samples = shares.into_iter().map(|(i, share)| (i, &share.0));
    //     let g = interpolate_g1(self.commit.degree(), samples)?;
    //     Ok(xor_with_hash(g, &ct.1))
    // }

    /// Combine two PublicKeySet into a single one (used from threshold generation)
    pub fn combine(&self, other: PublicKeySet) -> PublicKeySet {
        let mut commit = self.commit.clone();
        commit += &other.commit;
        PublicKeySet::from(commit)
    }
}
