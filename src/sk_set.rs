use crate::util::into_scalar_plus_1;
use crate::{IntoScalar, Poly, PublicKeySet, SecretKey, SecretKeyShare};
use anyhow::Result;
use rand::Rng;
use rand_core::RngCore;

/// A secret key and an associated set of secret key shares.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SecretKeySet {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    poly: Poly,
}

impl From<Poly> for SecretKeySet {
    fn from(poly: Poly) -> SecretKeySet {
        SecretKeySet { poly }
    }
}

impl SecretKeySet {
    /// Creates a set of secret key shares, where any `threshold + 1` of them can collaboratively
    /// sign and decrypt. This constructor is identical to the `SecretKeySet::try_random()` in every
    /// way except that this constructor panics if the other returns an error.
    ///
    /// # Panic
    ///
    /// Panics if the `threshold` is too large for the coefficients to fit into a `Vec`.
    pub fn random<R: Rng>(threshold: usize, rng: &mut R) -> Self {
        SecretKeySet::try_random(threshold, rng)
            .unwrap_or_else(|e| panic!("Failed to create random `SecretKeySet`: {}", e))
    }

    /// Creates a set of secret key shares, where any `threshold + 1` of them can collaboratively
    /// sign and decrypt. This constructor is identical to the `SecretKeySet::random()` in every
    /// way except that this constructor returns an `Err` where the `random` would panic.
    pub fn try_random<R: Rng>(threshold: usize, rng: &mut R) -> Result<Self> {
        Poly::try_random(threshold, rng).map(SecretKeySet::from)
    }

    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.poly.degree()
    }

    /// Returns the `i`-th secret key share.
    pub fn secret_key_share<T: IntoScalar>(&self, i: T) -> SecretKeyShare {
        let mut scalar = self.poly.evaluate(into_scalar_plus_1(i));
        SecretKeyShare::from_mut(&mut scalar)
    }

    /// Returns the corresponding public key set. That information can be shared publicly.
    pub fn public_keys(&self) -> PublicKeySet {
        PublicKeySet {
            commit: self.poly.commitment(),
        }
    }

    /// Returns the secret master key.
    #[cfg(test)]
    fn secret_key(&self) -> SecretKey {
        let mut fr = self.poly.evaluate(0);
        SecretKey::from_mut(&mut fr)
    }
}
