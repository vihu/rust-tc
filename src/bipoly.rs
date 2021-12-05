use crate::util::{clear_scalar, coeff_pos, powers};
use crate::{BivarCommitment, IntoScalar, Poly};
use anyhow::{bail, Result};
use bls12_381::{G1Affine, G1Projective, Scalar};
use ff::Field;
use rand::Rng;
use std::iter::{repeat_with, FromIterator};
use zeroize::Zeroize;

/// A symmetric bivariate polynomial in the prime field.
///
/// This can be used for Verifiable Secret Sharing and Distributed Key Generation. See the module
/// documentation for details.
#[derive(Clone, Debug)]
pub struct BivarPoly {
    /// The polynomial's degree in each of the two variables.
    degree: usize,
    /// The coefficients of the polynomial. Coefficient `(i, j)` for `i <= j` is in position
    /// `j * (j + 1) / 2 + i`.
    coeff: Vec<Scalar>,
}

impl Zeroize for BivarPoly {
    fn zeroize(&mut self) {
        for scalar in self.coeff.iter_mut() {
            clear_scalar(scalar)
        }
        self.degree.zeroize();
    }
}

impl Drop for BivarPoly {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl BivarPoly {
    /// Creates a random polynomial.
    ///
    /// # Panics
    ///
    /// Panics if the degree is too high for the coefficients to fit into a `Vec`.
    pub fn random(degree: usize) -> Self {
        let len = coeff_pos(degree, degree).and_then(|l| l.checked_add(1));

        let coeff: Vec<Scalar> = repeat_with(|| {
            let rng = rand::thread_rng();
            Scalar::random(rng)
        })
        .take(len.unwrap())
        .collect();
        BivarPoly { degree, coeff }
    }

    /// Creates a polynomial where the 0th coeff is set to `secret`.
    pub fn with_secret<T: IntoScalar>(secret: T, degree: usize) -> Self {
        let mut bipoly: BivarPoly = BivarPoly::random(degree);
        let mut coeff = bipoly.coeff.clone();
        coeff[0] = secret.into_scalar();
        bipoly.coeff = coeff;
        bipoly
    }

    /// Returns the polynomial's degree; which is the same in both variables.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the polynomial's value at the point `(x, y)`.
    pub fn evaluate<T: IntoScalar>(&self, x: T, y: T) -> Scalar {
        let x_pow = self.powers(x);
        let y_pow = self.powers(y);
        // TODO: Can we save a few multiplication steps here due to the symmetry?
        let mut result = Scalar::zero();
        for (i, x_pow_i) in x_pow.into_iter().enumerate() {
            for (j, y_pow_j) in y_pow.iter().enumerate() {
                let index = coeff_pos(i, j).expect("polynomial degree too high");
                let mut summand = self.coeff[index];
                summand *= &x_pow_i;
                summand *= y_pow_j;
                result += &summand;
            }
        }
        result
    }

    /// Returns the `x`-th row, as a univariate polynomial.
    pub fn row<T: IntoScalar>(&self, x: T) -> Poly {
        let x_pow = self.powers(x);
        let coeff: Vec<Scalar> = (0..=self.degree)
            .map(|i| {
                // TODO: clear these secrets from the stack.
                let mut result = Scalar::zero();
                for (j, x_pow_j) in x_pow.iter().enumerate() {
                    let index = coeff_pos(i, j).expect("polynomial degree too high");
                    let mut summand = self.coeff[index];
                    summand *= x_pow_j;
                    result += &summand;
                }
                result
            })
            .collect();
        Poly::from(coeff)
    }

    /// Returns the corresponding commitment. That information can be shared publicly.
    pub fn commitment(&self) -> BivarCommitment {
        let to_pub = |c: &Scalar| G1Affine::from(G1Projective::generator() * *c);
        BivarCommitment {
            degree: self.degree,
            coeff: self.coeff.iter().map(to_pub).collect(),
        }
    }

    /// Returns the `0`-th to `degree`-th power of `x`.
    fn powers<T: IntoScalar>(&self, x: T) -> Vec<Scalar> {
        powers(x, self.degree)
    }

    /// Generates a non-redacted debug string. This method differs from the
    /// `Debug` implementation in that it *does* leak the the struct's
    /// internal state.
    pub fn reveal(&self) -> String {
        format!(
            "BivarPoly {{ degree: {}, coeff: {:?} }}",
            self.degree, self.coeff
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::{G1Affine, G1Projective};
    use ff::Field;
    use std::collections::BTreeMap;

    #[test]
    fn bipoly_with_secret() {
        let degree: usize = 3;
        let secret: u64 = 42;
        let bipoly_with_secret = BivarPoly::with_secret(secret, degree);
        assert_eq!(secret.into_scalar(), bipoly_with_secret.coeff[0])
    }

    #[test]
    fn test_zeroize() {
        let mut poly = Poly::monomial(3) + Poly::monomial(2) - 1;
        poly.zeroize();
        assert!(poly.is_zero());

        let mut bi_poly = BivarPoly::random(3);
        let random_commitment = bi_poly.commitment();

        bi_poly.zeroize();

        let zero_commitment = bi_poly.commitment();
        assert_ne!(random_commitment, zero_commitment);

        let mut rng = rand::thread_rng();
        let (x, y): (Scalar, Scalar) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        assert_eq!(zero_commitment.evaluate(x, y), G1Projective::identity());
    }
}
