use crate::util::{clear_scalar, coeff_pos, powers};
use crate::{BivarCommitment, IntoScalar, Poly};
use anyhow::{bail, Result};
use bls12_381::{G1Affine, Scalar};
use ff::Field;
use rand::Rng;
use std::iter::repeat_with;
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
        let to_pub = |c: &Scalar| G1Affine::from(G1Affine::generator() * (*c));
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
        assert_eq!(zero_commitment.evaluate(x, y), G1Affine::identity());
    }

    #[test]
    fn distributed_key_generation() {
        let dealer_num = 3;
        let node_num = 5;
        let faulty_num = 2;

        // For distributed key generation, a number of dealers, only one of who needs to be honest,
        // generates random bivariate polynomials and publicly commits to them. In practice, the
        // dealers can e.g. be any `faulty_num + 1` nodes.
        let bi_polys: Vec<BivarPoly> = (0..dealer_num)
            .map(|_| BivarPoly::random(faulty_num))
            .collect();
        let pub_bi_commits: Vec<_> = bi_polys.iter().map(BivarPoly::commitment).collect();

        let mut sec_keys = vec![Scalar::zero(); node_num];

        // Each dealer sends row `m` to node `m`, where the index starts at `1`. Don't send row `0`
        // to anyone! The nodes verify their rows, and send _value_ `s` on to node `s`. They again
        // verify the values they received, and collect them.
        for (bi_poly, bi_commit) in bi_polys.iter().zip(&pub_bi_commits) {
            for m in 1..=node_num {
                // Node `m` receives its row and verifies it.
                let row_poly = bi_poly.row(m);
                let row_commit = bi_commit.row(m);
                assert_eq!(row_poly.commitment(), row_commit);
                // Node `s` receives the `s`-th value and verifies it.
                for s in 1..=node_num {
                    let val = row_poly.evaluate(s);
                    let val_g1 = G1Affine::from(G1Projective::generator() * val);
                    assert_eq!(bi_commit.evaluate(m, s), val_g1);
                    // The node can't verify this directly, but it should have the correct value:
                    assert_eq!(bi_poly.evaluate(m, s), val);
                }

                // A cheating dealer who modified the polynomial would be detected.
                let x_pow_2 = Poly::monomial(2);
                let five = Poly::constant(5.into_scalar());
                let wrong_poly = row_poly.clone() + x_pow_2 * five;
                assert_ne!(wrong_poly.commitment(), row_commit);

                // If `2 * faulty_num + 1` nodes confirm that they received a valid row, then at
                // least `faulty_num + 1` honest ones did, and sent the correct values on to node
                // `s`. So every node received at least `faulty_num + 1` correct entries of their
                // column/row (remember that the bivariate polynomial is symmetric). They can
                // reconstruct the full row and in particular value `0` (which no other node knows,
                // only the dealer). E.g. let's say nodes `1`, `2` and `4` are honest. Then node
                // `m` received three correct entries from that row:
                let received: BTreeMap<_, _> = [1, 2, 4]
                    .iter()
                    .map(|&i| (i, bi_poly.evaluate(m, i)))
                    .collect();
                let my_row = Poly::interpolate(received);
                assert_eq!(bi_poly.evaluate(m, 0), my_row.evaluate(0));
                assert_eq!(row_poly, my_row);

                // The node sums up all values number `0` it received from the different dealer. No
                // dealer and no other node knows the sum in the end.
                sec_keys[m - 1] += my_row.evaluate(Scalar::zero());
            }
        }

        // Each node now adds up all the first values of the rows it received from the different
        // dealers (excluding the dealers where fewer than `2 * faulty_num + 1` nodes confirmed).
        // The whole first column never gets added up in practice, because nobody has all the
        // information. We do it anyway here; entry `0` is the secret key that is not known to
        // anyone, neither a dealer, nor a node:
        let mut sec_key_set = Poly::zero();
        for bi_poly in &bi_polys {
            sec_key_set += bi_poly.row(0);
        }
        for m in 1..=node_num {
            assert_eq!(sec_key_set.evaluate(m), sec_keys[m - 1]);
        }

        // The sum of the first rows of the public commitments is the commitment to the secret key
        // set.
        let mut sum_commit = Poly::zero().commitment();
        for bi_commit in &pub_bi_commits {
            sum_commit += bi_commit.row(0);
        }
        assert_eq!(sum_commit, sec_key_set.commitment());
    }
}
