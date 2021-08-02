use bls12_381::Scalar;
use ff::PrimeField;

/// A conversion into a `Scalar`.
pub trait IntoScalar: Copy {
    /// Converts `self` to a field element.
    fn into_scalar(self) -> Scalar;
}

impl IntoScalar for Scalar {
    fn into_scalar(self) -> Scalar {
        self
    }
}

impl IntoScalar for u64 {
    fn into_scalar(self) -> Scalar {
        Scalar::from(self)
    }
}

impl IntoScalar for usize {
    fn into_scalar(self) -> Scalar {
        (self as u64).into_scalar()
    }
}

impl IntoScalar for i32 {
    fn into_scalar(self) -> Scalar {
        if self >= 0 {
            (self as u64).into_scalar()
        } else {
            -((-self) as u64).into_scalar()
        }
    }
}

impl IntoScalar for i64 {
    fn into_scalar(self) -> Scalar {
        if self >= 0 {
            (self as u64).into_scalar()
        } else {
            -((-self) as u64).into_scalar()
        }
    }
}

impl<'a, T: IntoScalar> IntoScalar for &'a T {
    fn into_scalar(self) -> Scalar {
        (*self).into_scalar()
    }
}
