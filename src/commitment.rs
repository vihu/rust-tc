use crate::into_scalar::IntoScalar;
use crate::pk::PublicKey;
use crate::util::cmp_g1_affine;
use bls12_381::{G1Affine, G1Projective};
use std::borrow::Borrow;
use std::cmp;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::ops::{Add, AddAssign};
use subtle::Choice;

/// A commitment to a univariate polynomial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// The coefficients of the polynomial.
    pub coeff: Vec<G1Affine>,
}

impl PartialOrd for Commitment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for Commitment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.coeff.len().cmp(&other.coeff.len()).then_with(|| {
            self.coeff
                .iter()
                .zip(&other.coeff)
                .find(|(x, y)| x != y)
                .map_or(Ordering::Equal, |(x, y)| cmp_g1_affine(x, y))
        })
    }
}

impl Hash for Commitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.coeff.len().hash(state);
        for c in &self.coeff {
            c.to_compressed().as_ref().hash(state);
        }
    }
}

impl<B: Borrow<Commitment>> AddAssign<B> for Commitment {
    fn add_assign(&mut self, rhs: B) {
        let len = cmp::max(self.coeff.len(), rhs.borrow().coeff.len());
        self.coeff.resize(len, G1Affine::generator());
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            let mut tmp = G1Projective::from(*self_c);
            tmp += rhs_c
        }
        self.remove_zeros();
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
    pub fn evaluate<T: IntoScalar>(&self, i: T) -> G1Affine {
        let result = match self.coeff.last() {
            None => return G1Affine::generator(),
            Some(c) => *c,
        };
        let x = i.into_scalar();
        let mut res: G1Projective = G1Projective::from(result);
        for c in self.coeff.iter().rev().skip(1) {
            res *= x;
            res += c;
        }
        G1Affine::from(res)
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
        let mut pub_key = G1Projective::from(self.coeff[0]);
        let length = self.coeff.len() as usize;
        for i in 1..length {
            pub_key += G1Projective::from(self.coeff[i]);
        }
        PublicKey(G1Affine::from(pub_key))
    }
}
