use crate::{pk::PublicKey, util::hash_g2};
use anyhow::{bail, Result};
use bls12_381::{
    multi_miller_loop, pairing, G1Affine, G2Affine, G2Prepared, G2Projective, Gt, MillerLoopResult,
    Scalar,
};
use std::ops::{AddAssign, Mul};

const SIGSIZE: usize = 96;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature(pub G2Affine);

impl Signature {
    pub fn validate(&self) -> bool {
        self.0.to_compressed().len() == SIGSIZE
    }
}

pub fn aggregate(sigs: &[Signature]) -> Result<Signature> {
    let agg = &sigs[0];

    if !agg.validate() {
        bail!("Cannot validate signature {:?}", agg)
    }

    let mut aggregate = G2Projective::from(sigs[0].0);

    for i in 1..sigs.len() {
        let next = &sigs[i];
        if !next.validate() {
            bail!("Cannot validate signature {:?}", next)
        }
        aggregate.add_assign(&next.0)
    }

    Ok(Signature(G2Affine::from(aggregate)))
}

pub fn core_aggregate_verify(
    signature: &Signature,
    hashes: &[G2Affine],
    public_keys: &[PublicKey],
) -> Result<bool> {
    // Either public_keys or hashes is empty, bail
    if hashes.is_empty() || public_keys.is_empty() {
        bail!(
            "Either hashes {:?} or public_keys {:?} is empty",
            hashes,
            public_keys
        )
    }

    // Bail if public_keys don't line up with hashes
    let num_hashes = hashes.len();
    if num_hashes != public_keys.len() {
        bail!("Length mismatch for public_keys and hashes!")
    }

    // Bail if non-unique hashes found!
    for i in 0..(num_hashes - 1) {
        for j in (i + 1)..num_hashes {
            let a = hashes[i];
            let b = hashes[j];
            if a == b {
                bail!("Non-unique hashes found! {:?} {:?}", a, b)
            }
        }
    }

    let c1: Gt = public_keys
        .iter()
        .zip(hashes.iter())
        .map(|(pk, h)| {
            let pk = pk.0;
            let h = G2Prepared::from(*h);
            multi_miller_loop(&[(&pk, &h)])
        })
        .fold(MillerLoopResult::default(), |mut acc, cur| {
            acc = acc.mul(&cur);
            acc
        })
        .final_exponentiation();

    let c2: Gt = pairing(&G1Affine::generator(), &signature.0);

    Ok(c1 == c2)
}

/// Verifies that the signature is the actual aggregated signature of messages - pubkeys.
/// Calculated by `e(g1, signature) == \prod_{i = 0}^n e(pk_i, hash_i)`.
pub fn verify_messages(
    signature: &Signature,
    messages: &[&[u8]],
    public_keys: &[PublicKey],
) -> Result<bool> {
    let hashes: Vec<_> = messages.iter().map(|msg| hash_g2(msg)).collect();

    core_aggregate_verify(signature, &hashes, public_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sk::SecretKey;

    #[test]
    fn aggregate_sig() {
        let sk1 = SecretKey::new();
        let pk1 = sk1.public_key();
        let sk2 = SecretKey::new();
        let pk2 = sk2.public_key();

        let msg1 = b"Rip and tear";
        let msg2 = b"till is done";

        let sig1 = sk1.sign(msg1);
        let sig2 = sk2.sign(msg2);

        if let Ok(agg_sig) = aggregate(&[sig1, sig2]) {
            if let Ok(res) = verify_messages(&agg_sig, &[msg1, msg2], &[pk1, pk2]) {
                assert!(res)
            }
        } else {
            assert!(false)
        }
    }

    #[test]
    fn valid() {
        let sk = SecretKey::new();
        let msg = b"Rip and tear, until it's done";
        let sig = sk.sign(msg);
        assert!(sig.validate())
    }
}
