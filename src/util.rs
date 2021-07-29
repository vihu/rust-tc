use bls12_381::{G2Affine, G2Projective};
use group::Group;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use tiny_keccak::{Hasher, Sha3};

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
