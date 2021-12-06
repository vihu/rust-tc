#[cfg(test)]
mod tests {
    use bls12_381::{G1Affine, G1Projective, Scalar};
    use std::time::Instant;

    #[test]
    fn mul_test() {
        let x: Scalar = Scalar::from(42);
        let zero = G1Projective::identity();
        let mut one = G1Projective::generator();
        let now = Instant::now();
        one *= &x;
        println!("time: {:?}", now.elapsed());
        println!("zero: {:#?}", zero);
        println!("one: {:#?}", one);
        assert_ne!(zero, one);
    }

    #[test]
    fn mul_test2() {
        let x: Scalar = Scalar::from(42);
        let zero = G1Affine::identity();
        let mut one = G1Affine::generator();
        let now = Instant::now();
        one *= &x;
        println!("time: {:?}", now.elapsed());
        println!("zero: {:#?}", zero);
        println!("one: {:#?}", one);
        assert_ne!(zero, one);
    }
}
