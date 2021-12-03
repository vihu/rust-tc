use crate::util::cmp_g1_projective;
use crate::{IntoScalar, PublicKey};
use bls12_381::{G1Affine, G1Projective};
use group::Curve;
use std::borrow::Borrow;
use std::cmp;
use std::hash::{Hash, Hasher};
use std::ops::{Add, AddAssign};
use subtle::Choice;

/// A commitment to a univariate polynomial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// The coefficients of the polynomial.
    pub coeff: Vec<G1Projective>,
}

impl PartialOrd for Commitment {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Commitment {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.coeff.len().cmp(&other.coeff.len()).then_with(|| {
            self.coeff
                .iter()
                .zip(&other.coeff)
                .find(|(x, y)| x != y)
                .map_or(cmp::Ordering::Equal, |(x, y)| cmp_g1_projective(x, y))
        })
    }
}

impl Hash for Commitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.coeff.len().hash(state);
        for c in &self.coeff {
            c.to_affine().to_compressed().as_ref().hash(state);
        }
    }
}

impl<B: Borrow<Commitment>> AddAssign<B> for Commitment {
    fn add_assign(&mut self, rhs: B) {
        let len = cmp::max(self.coeff.len(), rhs.borrow().coeff.len());
        self.coeff.resize(len, G1Projective::identity());
        let mut new_coeffs: Vec<G1Projective> = Vec::with_capacity(self.coeff.len());
        for (self_c, rhs_c) in self.coeff.iter().zip(&rhs.borrow().coeff) {
            new_coeffs.push(*self_c + *rhs_c)
        }
        *self = Commitment { coeff: new_coeffs };
        self.remove_zeros()
    }
}

impl<'a, B: Borrow<Commitment>> Add<B> for &'a Commitment {
    type Output = Commitment;

    fn add(self, rhs: B) -> Commitment {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Commitment>> Add<B> for Commitment {
    type Output = Commitment;

    fn add(mut self, rhs: B) -> Commitment {
        self += rhs;
        self
    }
}

impl Commitment {
    /// Returns the polynomial's degree.
    pub fn degree(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the `i`-th public key share.
    pub fn evaluate<T: IntoScalar>(&self, i: T) -> G1Projective {
        let mut res = match self.coeff.last() {
            None => return G1Projective::generator(),
            Some(c) => *c,
        };
        let x = i.into_scalar();
        for c in self.coeff.iter().rev().skip(1) {
            res *= x;
            res += c;
        }
        res
    }

    /// Removes all trailing zero coefficients.
    fn remove_zeros(&mut self) {
        let zeros = self
            .coeff
            .iter()
            .rev()
            .take_while(|c| bool::from(c.is_identity()))
            .count();
        let len = self.coeff.len() - zeros;
        self.coeff.truncate(len)
    }

    /// Generates a public key from a commitment
    pub fn public_key(&self) -> PublicKey {
        let mut pub_key = self.coeff[0];
        let length = self.coeff.len() as usize;
        for i in 1..length {
            pub_key += self.coeff[i];
        }
        PublicKey(pub_key.to_affine())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{Poly, PublicKeySet, SecretKeySet};

    #[test]
    fn basic() {
        // p1 = 5 X³ + X - 2.
        let x_pow_3 = Poly::monomial(3);
        let x_pow_1 = Poly::monomial(1);
        let poly = x_pow_3 * 5 + x_pow_1 - 2;

        let sks = SecretKeySet::from(poly.clone());

        let c = poly.commitment();

        let pks = PublicKeySet::from(c);

        assert_eq!(pks, sks.public_keys())
    }
}
