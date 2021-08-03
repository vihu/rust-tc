use crate::util::{cmp_g1_affine, coeff_pos, powers};
use crate::{Commitment, IntoScalar};
use bls12_381::{G1Affine, G1Projective, Scalar};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::ops::MulAssign;

/// A commitment to a symmetric bivariate polynomial.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BivarCommitment {
    /// The polynomial's degree in each of the two variables.
    pub(crate) degree: usize,
    /// The commitments to the coefficients.
    pub(crate) coeff: Vec<G1Affine>,
}

impl Hash for BivarCommitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.degree.hash(state);
        for c in &self.coeff {
            c.to_compressed().as_ref().hash(state);
        }
    }
}

impl PartialOrd for BivarCommitment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for BivarCommitment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.degree.cmp(&other.degree).then_with(|| {
            self.coeff
                .iter()
                .zip(&other.coeff)
                .find(|(x, y)| x != y)
                .map_or(Ordering::Equal, |(x, y)| cmp_g1_affine(x, y))
        })
    }
}

impl BivarCommitment {
    /// Returns the polynomial's degree: It is the same in both variables.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the commitment's value at the point `(x, y)`.
    pub fn evaluate<T: IntoScalar>(&self, x: T, y: T) -> G1Affine {
        let x_pow = self.powers(x);
        let y_pow = self.powers(y);
        // TODO: Can we save a few multiplication steps here due to the symmetry?
        let mut result = G1Projective::identity();
        for (i, x_pow_i) in x_pow.into_iter().enumerate() {
            for (j, y_pow_j) in y_pow.iter().enumerate() {
                let index = coeff_pos(i, j).expect("polynomial degree too high");
                let mut summand = G1Projective::from(self.coeff[index]);
                summand.mul_assign(x_pow_i);
                summand.mul_assign(*y_pow_j);
                result = result.add(&summand);
            }
        }
        G1Affine::from(result)
    }

    /// Returns the `x`-th row, as a commitment to a univariate polynomial.
    pub fn row<T: IntoScalar>(&self, x: T) -> Commitment {
        let x_pow = self.powers(x);
        let coeff: Vec<G1Affine> = (0..=self.degree)
            .map(|i| {
                let mut result = G1Projective::identity();
                for (j, x_pow_j) in x_pow.iter().enumerate() {
                    let index = coeff_pos(i, j).expect("polynomial degree too high");
                    let mut summand = G1Projective::from(self.coeff[index]);
                    summand *= x_pow_j;
                    result += &summand;
                }
                G1Affine::from(result)
            })
            .collect();
        Commitment { coeff }
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
            "BivarCommitment {{ degree: {}, coeff: {:?} }}",
            self.degree, self.coeff
        )
    }
}
