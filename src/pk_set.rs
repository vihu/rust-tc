use crate::util::*;
use crate::{
    Ciphertext, Commitment, DecryptionShare, IntoScalar, PublicKey, PublicKeyShare, Signature,
    SignatureShare,
};
use anyhow::{anyhow, bail, Result};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
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

    pub fn combine_signatures<'a, T, I>(&self, shares: I) -> Result<Signature>
    where
        I: IntoIterator<Item = (T, &'a SignatureShare)>,
        T: IntoScalar,
    {
        let samples = shares.into_iter().map(|(i, share)| (i, &(share.0).0));
        Ok(Signature(combine_signatures_(
            self.commit.degree(),
            samples,
        )?))
    }

    /// Combine two PublicKeySet into a single one (used from threshold generation)
    pub fn combine(&self, other: PublicKeySet) -> PublicKeySet {
        let mut commit = self.commit.clone();
        commit += &other.commit;
        PublicKeySet::from(commit)
    }

    pub fn decrypt<'a, T, I>(&self, shares: I, ct: &Ciphertext) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = (T, &'a DecryptionShare)>,
        T: IntoScalar,
    {
        let samples = shares.into_iter().map(|(i, share)| (i, &share.0));
        let g = decrypt_(self.commit.degree(), samples)?;
        Ok(xor_with_hash(g, &ct.1))
    }
}

// TODO: Figure out how to combine these two functions

fn decrypt_<B, T, I>(t: usize, items: I) -> Result<G1Affine>
where
    I: IntoIterator<Item = (T, B)>,
    T: IntoScalar,
    B: Borrow<G1Affine>,
{
    let samples: Vec<_> = items
        .into_iter()
        .take(t + 1)
        .map(|(i, sample)| (into_scalar_plus_1(i), sample))
        .collect();
    if samples.len() <= t {
        bail!("not enough shares")
    }

    if t == 0 {
        return Ok(*samples[0].1.borrow());
    }

    // Compute the products `x_prod[i]` of all but the `i`-th entry.
    let mut x_prod: Vec<Scalar> = Vec::with_capacity(t);
    let mut tmp = Scalar::one();
    x_prod.push(tmp);
    for (x, _) in samples.iter().take(t) {
        tmp *= x;
        x_prod.push(tmp);
    }
    tmp = Scalar::one();
    for (i, (x, _)) in samples[1..].iter().enumerate().rev() {
        tmp *= x;
        x_prod[i] *= &tmp;
    }

    let mut result = G1Projective::identity();
    for (mut l0, (x, sample)) in x_prod.into_iter().zip(&samples) {
        // Compute the value at 0 of the Lagrange polynomial that is `0` at the other data
        // points but `1` at `x`.
        let mut denom = Scalar::one();
        for (x0, _) in samples.iter().filter(|(x0, _)| x0 != x) {
            let mut diff = *x0;
            diff -= x;
            denom *= &diff;
        }
        l0 *= &denom.invert().unwrap();
        result += sample.borrow() * l0;
    }
    Ok(G1Affine::from(result))
}

fn combine_signatures_<B, T, I>(t: usize, items: I) -> Result<G2Affine>
where
    I: IntoIterator<Item = (T, B)>,
    T: IntoScalar,
    B: Borrow<G2Affine>,
{
    let samples: Vec<_> = items
        .into_iter()
        .take(t + 1)
        .map(|(i, sample)| (into_scalar_plus_1(i), sample))
        .collect();
    if samples.len() <= t {
        bail!("not enough shares")
    }

    if t == 0 {
        return Ok(*samples[0].1.borrow());
    }

    // Compute the products `x_prod[i]` of all but the `i`-th entry.
    let mut x_prod: Vec<Scalar> = Vec::with_capacity(t);
    let mut tmp = Scalar::one();
    x_prod.push(tmp);
    for (x, _) in samples.iter().take(t) {
        tmp *= x;
        x_prod.push(tmp);
    }
    tmp = Scalar::one();
    for (i, (x, _)) in samples[1..].iter().enumerate().rev() {
        tmp *= x;
        x_prod[i] *= &tmp;
    }

    let mut result = G2Projective::identity();
    for (mut l0, (x, sample)) in x_prod.into_iter().zip(&samples) {
        // Compute the value at 0 of the Lagrange polynomial that is `0` at the other data
        // points but `1` at `x`.
        let mut denom = Scalar::one();
        for (x0, _) in samples.iter().filter(|(x0, _)| x0 != x) {
            let mut diff = *x0;
            diff -= x;
            denom *= &diff;
        }
        l0 *= &denom.invert().unwrap();
        result += sample.borrow() * l0;
    }
    Ok(G2Affine::from(result))
}
