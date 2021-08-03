use bls12_381::Scalar;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion};
use ff::Field;
use rust_tc::Poly;

const TEST_DEGREES: [usize; 4] = [5, 10, 20, 40];
const TEST_THRESHOLDS: [usize; 4] = [5, 10, 20, 40];
const RNG_SEED: [u8; 16] = *b"0123456789abcdef";

mod poly_benches {
    use super::*;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    /// Benchmarks multiplication of two polynomials.
    fn bench_poly_multiplication(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("poly_multiplication");
        for degree in TEST_DEGREES.iter() {
            group.bench_with_input(BenchmarkId::from_parameter(degree), degree, |b, &degree| {
                b.iter(|| {
                    let lhs = Poly::random(degree, &mut rng);
                    let rhs = Poly::random(degree, &mut rng);
                    lhs * rhs
                })
            });
        }
        group.finish();
    }

    /// Benchmarks subtraction of two polynomials
    fn bench_poly_subtraction(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("poly_subtraction");
        for degree in TEST_DEGREES.iter() {
            group.bench_with_input(BenchmarkId::from_parameter(degree), degree, |b, &degree| {
                b.iter(|| {
                    let lhs = Poly::random(degree, &mut rng);
                    let rhs = Poly::random(degree, &mut rng);
                    lhs - rhs
                })
            });
        }
        group.finish();
    }

    /// Benchmarks addition of two polynomials
    fn bench_poly_addition(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("poly_addition");
        for degree in TEST_DEGREES.iter() {
            group.bench_with_input(BenchmarkId::from_parameter(degree), degree, |b, &degree| {
                b.iter(|| {
                    let lhs = Poly::random(degree, &mut rng);
                    let rhs = Poly::random(degree, &mut rng);
                    lhs + rhs
                })
            });
        }
        group.finish();
    }

    /// Benchmarks Lagrange interpolation for a polynomial.
    fn bench_poly_interpolation(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("poly_interpolation");
        for degree in TEST_DEGREES.iter() {
            group.bench_with_input(BenchmarkId::from_parameter(degree), degree, |b, &degree| {
                b.iter(|| {
                    let samples = (0..=degree)
                        .map(|i| (i, Scalar::random(&mut rng)))
                        .collect::<Vec<_>>();
                    Poly::interpolate(samples)
                })
            });
        }
        group.finish();
    }

    criterion_group! {
        name = poly_benches;
        config = Criterion::default();
        targets = bench_poly_multiplication, bench_poly_interpolation, bench_poly_addition, bench_poly_subtraction,
    }
}

mod public_key_set_benches {
    use super::*;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use rust_tc::SecretKeySet;
    use std::collections::BTreeMap;

    /// Benchmarks combining signatures
    fn bench_combine_signatures(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let msg = "Test message";
        let mut group = c.benchmark_group("combine_signatures");
        for threshold in TEST_THRESHOLDS.iter() {
            group.bench_with_input(
                BenchmarkId::from_parameter(threshold),
                threshold,
                |b, &threshold| {
                    b.iter(|| {
                        let sk_set = SecretKeySet::random(threshold, &mut rng);
                        let pk_set = sk_set.public_keys();
                        let sigs: BTreeMap<_, _> = (0..=threshold)
                            .map(|i| {
                                let sig = sk_set.secret_key_share(i).sign(msg);
                                (i, sig)
                            })
                            .collect();
                        pk_set
                            .combine_signatures(&sigs)
                            .expect("unable to combine_signatures")
                    })
                },
            );
        }
        group.finish();
    }

    criterion_group! {
        name = public_key_set_benches;
        config = Criterion::default();
        targets = bench_combine_signatures,
    }
}

criterion_main!(
    poly_benches::poly_benches,
    public_key_set_benches::public_key_set_benches
);
