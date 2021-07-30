use crate::{pk::PublicKey, util::hash_g2};
use anyhow::{bail, Result};
use bls12_381::{pairing, G1Affine, G2Affine, G2Projective, Gt, Scalar};
use std::ops::{AddAssign, Mul};

const SIGSIZE: usize = 96;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature(pub G2Affine);

impl Signature {
    pub fn validate(&self) -> bool {
        self.0.to_compressed().len() == SIGSIZE
    }

    pub fn aggregate(sigs: &[Signature]) -> Result<Signature> {
        let agg = &sigs[0];

        if !agg.validate() {
            bail!("Cannot validate signature {:?}", agg)
        }

        let mut aggregate = G2Projective::from(sigs[0].0);

        for i in 2..sigs.len() {
            let next = &sigs[i];
            if !next.validate() {
                bail!("Cannot validate signature {:?}", next)
            }
            aggregate.add_assign(&next.0)
        }

        Ok(Signature(G2Affine::from(aggregate)))
    }

    // TODO: Fix me
    // pub fn core_aggregate_verify<M: AsRef<[u8]>>(
    //     public_keys: &[PublicKey],
    //     msgs: &[M],
    //     sig: Signature,
    // ) -> Result<bool> {
    //     if !sig.validate() {
    //         bail!("Invalid signature: {:?}", sig);
    //     }

    //     // check there are some keys and msgs
    //     if public_keys.len() < 1 || msgs.len() < 1 {
    //         bail!("Invalid public_keys or msgs length");
    //     }

    //     // check that the lengths match
    //     if public_keys.len() != msgs.len() {
    //         bail!("Invalid public_keys and msgs length don't match!")
    //     }

    //     let mut c1 = Gt::identity();

    //     for i in 1..public_keys.len() {
    //         let pk = public_keys[i];
    //         if !pk.validate() {
    //             bail!("Invalid public_key: {:?}", pk)
    //         }
    //         let p = public_keys[i].0;
    //         let q = hash_g2(msgs[i]);
    //         let gt = pairing(&p, &q);
    //         c1 = gt * c1;
    //     }
    //     let c2 = pairing(&G1Affine::generator(), &sig.0);
    //     Ok(c1 == c2)
    // }
}

#[cfg(test)]
mod tests {
    use super::Signature;
    use crate::sk::SecretKey;
    // use bls12_381::{Gt, Scalar};
    // use ff::Field;
    // use rand::thread_rng;
    // use std::ops::Mul;

    #[test]
    fn aggregate_sig() {
        let sigs = (0u32..10)
            .map(|_| SecretKey::new().sign("sign me"))
            .collect::<Vec<Signature>>();
        let agg_sig = Signature::aggregate(&sigs);
        println!("agg_sig: {:?}", agg_sig)
    }

    #[test]
    fn valid() {
        let sk = SecretKey::new();
        let msg = b"Rip and tear, until it's done";
        let sig = sk.sign(msg);
        assert!(sig.validate())
    }
}
