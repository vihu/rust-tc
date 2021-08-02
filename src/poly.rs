use crate::commitment::Commitment;
use crate::into_scalar::IntoScalar;
use crate::util::clear_scalar;
use anyhow::{bail, Result};
use bls12_381::{G1Affine, Scalar};
use ff::Field;
use rand::Rng;
use rand_core::RngCore;
use std::borrow::Borrow;
use std::iter;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use zeroize::Zeroize;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Poly {
    /// The coefficients of a polynomial.
    pub coeff: Vec<Scalar>,
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        for scalar in self.coeff.iter_mut() {
            clear_scalar(scalar)
        }
    }
}

/// Creates a new `Poly` instance from a vector of Scalar elements representing the
/// coefficients of the polynomial.
impl From<Vec<Scalar>> for Poly {
    fn from(coeff: Vec<Scalar>) -> Self {
        Poly { coeff }
    }
}

impl Poly {
    /// Returns the degree.
    pub fn degree(&self) -> usize {
        self.coeff.len().saturating_sub(1)
    }

    /// Returns the polynomial with constant value `0`.
    pub fn zero() -> Self {
        Poly { coeff: vec![] }
    }

    /// Returns `true` if the polynomial is the constant value `0`.
    pub fn is_zero(&self) -> bool {
        self.coeff.iter().all(|coeff| coeff.is_zero())
    }

    /// Returns the polynomial with constant value `1`.
    pub fn one() -> Self {
        Poly::constant(Scalar::one())
    }

    /// Returns the polynomial with constant value `c`.
    pub fn constant(c: Scalar) -> Self {
        Poly::from(vec![c])
    }

    /// Returns the identity function, i.e. the polynomial "`x`".
    pub fn identity() -> Self {
        Poly::monomial(1)
    }

    /// Returns the (monic) monomial: `x.pow(degree)`.
    pub fn monomial(degree: usize) -> Self {
        let coeff: Vec<Scalar> = iter::repeat(Scalar::zero())
            .take(degree)
            .chain(iter::once(Scalar::one()))
            .collect();
        Poly::from(coeff)
    }

    pub fn random(degree: usize) -> Self {
        let coeff: Vec<Scalar> = iter::repeat_with(|| {
            let rng = rand::thread_rng();
            Scalar::random(rng)
        })
        .take(degree + 1)
        .collect();

        Poly::from(coeff)
    }

    /// Removes all trailing zero coefficients.
    fn remove_zeros(&mut self) {
        let zeros = self.coeff.iter().rev().take_while(|c| c.is_zero()).count();
        let len = self.coeff.len() - zeros;
        self.coeff.truncate(len);
    }

    /// Returns the value at the point `i`.
    pub fn evaluate<T: IntoScalar>(&self, i: T) -> Scalar {
        let mut result = match self.coeff.last() {
            None => return Scalar::zero(),
            Some(c) => *c,
        };
        let x = i.into_scalar();
        for c in self.coeff.iter().rev().skip(1) {
            result.mul_assign(&x);
            result.add_assign(c);
        }
        result
    }

    /// Returns the unique polynomial `f` of degree `samples.len() - 1` with the given values
    /// `(x, f(x))`.
    pub fn interpolate<T, U, I>(samples_repr: I) -> Self
    where
        I: IntoIterator<Item = (T, U)>,
        T: IntoScalar,
        U: IntoScalar,
    {
        let convert = |(x, y): (T, U)| (x.into_scalar(), y.into_scalar());
        let samples: Vec<(Scalar, Scalar)> = samples_repr.into_iter().map(convert).collect();
        Poly::compute_interpolation(&samples)
    }

    /// Returns the unique polynomial `f` of degree `samples.len() - 1` with the given values
    /// `(x, f(x))`.
    fn compute_interpolation(samples: &[(Scalar, Scalar)]) -> Self {
        if samples.is_empty() {
            return Poly::zero();
        }
        // Interpolates on the first `i` samples.
        let mut poly = Poly::constant(samples[0].1);
        let minus_s0 = -samples[0].0;
        // Is zero on the first `i` samples.
        let mut base = Poly::from(vec![minus_s0, Scalar::one()]);

        // We update `base` so that it is always zero on all previous samples, and `poly` so that
        // it has the correct values on the previous samples.
        for (ref x, ref y) in &samples[1..] {
            // Scale `base` so that its value at `x` is the difference between `y` and `poly`'s
            // current value at `x`: Adding it to `poly` will then make it correct for `x`.
            let mut diff = *y;
            diff.sub_assign(&poly.evaluate(x));
            let base_val = base.evaluate(x);
            diff.mul_assign(&base_val.invert().unwrap());
            base *= diff;
            poly += &base;

            // Finally, multiply `base` by X - x, so that it is zero at `x`, too, now.
            let minus_x = -(*x);
            base *= Poly::from(vec![minus_x, Scalar::one()]);
        }
        poly
    }

    /// Returns the corresponding commitment.
    pub fn commitment(&self) -> Commitment {
        let to_g1 = |c: &Scalar| G1Affine::from(G1Affine::generator().mul(*c));
        Commitment {
            coeff: self.coeff.iter().map(to_g1).collect(),
        }
    }
}

impl<B: Borrow<Poly>> AddAssign<B> for Poly {
    fn add_assign(&mut self, rhs: B) {
        let len = self.coeff.len();
        let rhs_len = rhs.borrow().coeff.len();
        if rhs_len > len {
            self.coeff.resize(rhs_len, Scalar::zero());
        }
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.add_assign(rhs_c)
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Poly>> Add<B> for &'a Poly {
    type Output = Poly;

    fn add(self, rhs: B) -> Poly {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Poly>> Add<B> for Poly {
    type Output = Poly;

    fn add(mut self, rhs: B) -> Poly {
        self += rhs;
        self
    }
}

impl<'a> Add<Scalar> for Poly {
    type Output = Poly;

    fn add(mut self, rhs: Scalar) -> Self::Output {
        if self.is_zero() && !rhs.is_zero() {
            self.coeff.push(rhs);
        } else {
            self.coeff[0].add_assign(&rhs);
            self.remove_zeros();
        }
        self
    }
}

impl<'a> Add<u64> for Poly {
    type Output = Poly;

    fn add(self, rhs: u64) -> Self::Output {
        self + rhs.into_scalar()
    }
}

impl<B: Borrow<Poly>> SubAssign<B> for Poly {
    fn sub_assign(&mut self, rhs: B) {
        let len = self.coeff.len();
        let rhs_len = rhs.borrow().coeff.len();
        if rhs_len > len {
            self.coeff.resize(rhs_len, Scalar::zero());
        }
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.sub_assign(rhs_c)
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Poly>> Sub<B> for &'a Poly {
    type Output = Poly;

    fn sub(self, rhs: B) -> Poly {
        (*self).clone() - rhs
    }
}

impl<B: Borrow<Poly>> Sub<B> for Poly {
    type Output = Poly;

    fn sub(mut self, rhs: B) -> Poly {
        self -= rhs;
        self
    }
}

impl<'a> Sub<Scalar> for Poly {
    type Output = Poly;

    fn sub(self, rhs: Scalar) -> Self::Output {
        let neg = rhs.neg();
        self + neg
    }
}

impl<'a> Sub<u64> for Poly {
    type Output = Poly;

    fn sub(self, rhs: u64) -> Self::Output {
        self - rhs.into_scalar()
    }
}

impl<'a, B: Borrow<Poly>> Mul<B> for &'a Poly {
    type Output = Poly;

    fn mul(self, rhs: B) -> Self::Output {
        let rhs = rhs.borrow();
        if rhs.is_zero() || self.is_zero() {
            return Poly::zero();
        }
        let n_coeffs = self.coeff.len() + rhs.coeff.len() - 1;
        let mut coeffs = vec![Scalar::zero(); n_coeffs];
        let mut tmp = Scalar::zero();
        for (i, ca) in self.coeff.iter().enumerate() {
            for (j, cb) in rhs.coeff.iter().enumerate() {
                tmp = *ca;
                tmp.mul_assign(cb);
                coeffs[i + j].add_assign(&tmp);
            }
        }
        clear_scalar(&mut tmp);
        Poly::from(coeffs)
    }
}

impl<B: Borrow<Poly>> Mul<B> for Poly {
    type Output = Poly;

    fn mul(self, rhs: B) -> Self::Output {
        &self * rhs
    }
}

impl<B: Borrow<Self>> MulAssign<B> for Poly {
    fn mul_assign(&mut self, rhs: B) {
        *self = &*self * rhs;
    }
}

impl MulAssign<Scalar> for Poly {
    fn mul_assign(&mut self, rhs: Scalar) {
        if rhs.is_zero() {
            self.zeroize();
            self.coeff.clear();
        } else {
            for c in &mut self.coeff {
                c.mul_assign(rhs)
            }
        }
    }
}

impl<'a> Mul<&'a Scalar> for Poly {
    type Output = Poly;

    fn mul(mut self, rhs: &Scalar) -> Self::Output {
        if rhs.is_zero() {
            self.zeroize();
            self.coeff.clear();
        } else {
            self.coeff.iter_mut().for_each(|c| c.mul_assign(rhs));
        }
        self
    }
}

impl Mul<Scalar> for Poly {
    type Output = Poly;

    fn mul(self, rhs: Scalar) -> Self::Output {
        let rhs = &rhs;
        self * rhs
    }
}

impl<'a> Mul<&'a Scalar> for &'a Poly {
    type Output = Poly;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        (*self).clone() * rhs
    }
}

impl<'a> Mul<Scalar> for &'a Poly {
    type Output = Poly;

    fn mul(self, rhs: Scalar) -> Self::Output {
        (*self).clone() * rhs
    }
}

impl Mul<u64> for Poly {
    type Output = Poly;

    fn mul(self, rhs: u64) -> Self::Output {
        self * rhs.into_scalar()
    }
}

/// Returns the position of coefficient `(i, j)` in the vector describing a symmetric bivariate
/// polynomial. If `i` or `j` are too large to represent the position as a `usize`, `None` is
/// returned.
pub(crate) fn coeff_pos(i: usize, j: usize) -> Option<usize> {
    // Since the polynomial is symmetric, we can order such that `j >= i`.
    let (j, i) = if j >= i { (j, i) } else { (i, j) };
    i.checked_add(j.checked_mul(j.checked_add(1)?)? / 2)
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::{thread_rng, Rng};

    #[test]
    fn rand_degree() {
        let deg = 2;
        let p = Poly::random(deg);
        assert_eq!(deg, p.degree())
    }

    #[test]
    fn add() {
        let p1 = Poly::from(vec![Scalar::zero(), Scalar::one()]);
        let p2 = Poly::from(vec![Scalar::one(), Scalar::zero()]);
        let expected = Poly::from(vec![Scalar::one(), Scalar::one()]);
        assert_eq!(expected, p1 + p2);

        let p3 = Poly::from(vec![]);
        let p4 = Poly::from(vec![Scalar::one()]);
        assert_eq!(Poly::from(vec![Scalar::one()]), p3 + p4)
    }

    #[test]
    fn add_diff_degree() {
        let p1 = Poly::from(vec![Scalar::one(), Scalar::one(), Scalar::one()]);
        let p2 = Poly::from(vec![Scalar::zero(), Scalar::zero()]);
        let expected = Poly::from(vec![Scalar::one(), Scalar::one(), Scalar::one()]);
        assert_eq!(expected, p1.clone() + p2.clone());

        let p3 = Poly::from(vec![
            Scalar::zero(),
            Scalar::zero(),
            Scalar::zero(),
            Scalar::one(),
        ]);
        let expected2 = Poly::from(vec![
            Scalar::one(),
            Scalar::one(),
            Scalar::one(),
            Scalar::one(),
        ]);
        assert_eq!(expected2, (p1 + p2) + p3)
    }

    #[test]
    fn mul() {
        // f(x) = x + 1
        let p1 = Poly::from(vec![Scalar::one(), Scalar::one()]);
        // g(x) = x
        let p2 = Poly::from(vec![Scalar::zero(), Scalar::one()]);
        // h(x) = x*x + x
        let expected = Poly::from(vec![Scalar::zero(), Scalar::one(), Scalar::one()]);
        assert_eq!(expected, p1.mul(&p2));
    }

    #[test]
    fn full() {
        // p1 = 5 X³ + X - 2.
        let x_pow_3 = Poly::monomial(3);
        let x_pow_1 = Poly::monomial(1);
        let p1 = x_pow_3 * 5 + x_pow_1 - 2;

        let coeff: Vec<Scalar> = [-2, 1, 0, 5].iter().map(IntoScalar::into_scalar).collect();
        let p2 = Poly::from(coeff);
        assert_eq!(p2, p1);
        let samples = vec![(-1, -8), (2, 40), (3, 136), (5, 628)];
        for &(x, y) in &samples {
            assert_eq!(y.into_scalar(), p1.evaluate(x));
        }
        let interp = Poly::interpolate(samples);
        assert_eq!(interp, p1);
    }

    #[test]
    fn zeroize() {
        let mut poly = Poly::monomial(3) + Poly::monomial(2) - 1;
        poly.zeroize();
        assert!(poly.is_zero());
    }

    #[test]
    fn test_coeff_pos() {
        let mut i = 0;
        let mut j = 0;
        for n in 0..100 {
            assert_eq!(Some(n), coeff_pos(i, j));
            if i >= j {
                j += 1;
                i = 0;
            } else {
                i += 1;
            }
        }
        let too_large = 1 << (0usize.count_zeros() / 2);
        assert_eq!(None, coeff_pos(0, too_large));
    }
}
