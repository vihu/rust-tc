use bls12_381::Scalar;
use bls12_381::{G1Affine, G2Affine, G2Projective};
use group::Group;
use rand::distributions::Standard;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use tiny_keccak::{Hasher, Sha3};
use zeroize::Zeroize;

/// Fancy new sha3
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    sha3.update(data);
    let mut output = [0u8; 32];
    sha3.finalize(&mut output);
    output
}

/// Returns a hash of the given message in `G2Affine` space.
pub fn hash_g2<M: AsRef<[u8]>>(msg: M) -> G2Affine {
    let digest = sha3_256(msg.as_ref());
    G2Affine::from(G2Projective::random(&mut ChaChaRng::from_seed(digest)))
}

/// Returns the bitwise xor of `bytes` with a sequence of pseudorandom bytes determined by `g1`.
pub fn xor_with_hash(g1: G1Affine, bytes: &[u8]) -> Vec<u8> {
    let digest = sha3_256(g1.to_compressed().as_ref());
    let rng = ChaChaRng::from_seed(digest);
    let xor = |(a, b): (u8, &u8)| a ^ b;
    rng.sample_iter(&Standard).zip(bytes).map(xor).collect()
}

/// Returns a hash of the group element and message, in the second group.
pub fn hash_g1_g2<M: AsRef<[u8]>>(g1: G1Affine, msg: M) -> G2Affine {
    // If the message is large, hash it, otherwise copy it.
    // TODO: Benchmark and optimize the threshold.
    let mut msg = if msg.as_ref().len() > 64 {
        sha3_256(msg.as_ref()).to_vec()
    } else {
        msg.as_ref().to_vec()
    };
    msg.extend(g1.to_compressed().as_ref());
    hash_g2(&msg)
}

/// Overwrites a single field element with zeros.
pub fn clear_scalar(scalar: &mut Scalar) {
    type Repr = [u64; 4];

    // TODO: Remove this after pairing support `Zeroize`
    let fr_repr = unsafe { &mut *(scalar as *mut Scalar as *mut Repr) };
    fr_repr[0].zeroize();
    fr_repr[1].zeroize();
    fr_repr[2].zeroize();
    fr_repr[3].zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand::thread_rng;

    #[test]
    fn test_clear() {
        let mut rng = thread_rng();

        let mut scalar: Scalar = Scalar::random(&mut rng);
        assert_ne!(scalar, Scalar::zero());

        clear_scalar(&mut scalar);
        assert_eq!(scalar, Scalar::zero());
    }
}
