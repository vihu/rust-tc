use crate::{pk::PublicKey, util::hash_g2};
use anyhow::{bail, Result};
use bls12_381::{
    multi_miller_loop, pairing, G1Affine, G2Affine, G2Prepared, G2Projective, Gt, MillerLoopResult,
    Scalar,
};
use group::Curve;
use serde::de::{self, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use std::convert::TryInto;
use std::fmt;
use std::ops::{AddAssign, Mul};

const SIGSIZE: usize = 96;

#[derive(Clone, PartialEq, Eq, Debug, Copy)]
pub struct Signature(pub G2Affine);

impl Signature {
    pub fn is_valid(&self) -> bool {
        self.0.to_compressed().len() == SIGSIZE
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0.to_compressed())
    }
}

struct SigVisitor;

fn coerce_size(v: &[u8]) -> &[u8; SIGSIZE] {
    v.try_into().expect("Signature with incorrect length")
}

impl<'de> Visitor<'de> for SigVisitor {
    type Value = Signature;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an integer between -2^31 and 2^31")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Signature(
            G2Affine::from_compressed(coerce_size(v)).unwrap(),
        ))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SigVisitor)
    }
}

pub fn aggregate(sigs: &[Signature]) -> Result<Signature> {
    let agg = &sigs[0];

    if !agg.is_valid() {
        bail!("Cannot validate signature {:?}", agg)
    }

    let mut aggregate = G2Projective::from(sigs[0].0);

    for i in 1..sigs.len() {
        let next = &sigs[i];
        if !next.is_valid() {
            bail!("Cannot validate signature {:?}", next)
        }
        aggregate.add_assign(&next.0)
    }

    Ok(Signature(aggregate.to_affine()))
}

pub fn core_aggregate_verify(
    signature: &Signature,
    hashes: &[G2Projective],
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
            let pk = G1Affine::from(pk.0);
            let h = G2Prepared::from(G2Affine::from(*h));
            multi_miller_loop(&[(&pk, &h)])
        })
        .fold(MillerLoopResult::default(), |mut acc, cur| {
            acc = acc.mul(&cur);
            acc
        })
        .final_exponentiation();

    let c2: Gt = pairing(&G1Affine::generator(), &G2Affine::from(signature.0));

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
    use core::panic;

    use super::*;
    use crate::sk::SecretKey;

    #[test]
    fn verify_agg() {
        let sk1 = SecretKey::random();
        let pk1 = sk1.public_key();
        let sk2 = SecretKey::random();
        let pk2 = sk2.public_key();
        let msg1 = b"Rip and tear";
        let msg2 = b"till is done";

        let sig1 = sk1.sign(msg1);
        let sig2 = sk2.sign(msg2);

        if let Ok(agg_sig) = aggregate(&[sig1, sig2]) {
            println!("sig: {:?}", agg_sig);
            if let Ok(res) = verify_messages(&agg_sig, &[msg1, msg2], &[pk1, pk2]) {
                assert!(res)
            } else {
                assert!(false)
            }
        } else {
            assert!(false)
        }
    }

    #[test]
    fn is_valid_sig() {
        let sk = SecretKey::random();
        let msg = b"Rip and tear, until it's done";
        let sig = sk.sign(msg);
        assert!(sig.is_valid())
    }

    #[test]
    fn sig_serde_roundtrip() {
        let sk = SecretKey::random();
        let msg = b"Rip and tear, until it's done";
        let sig = sk.sign(msg);

        let bin_sig = bincode::serialize(&sig).expect("boom serialize sig");
        let deser_sig: Signature =
            bincode::deserialize(&bin_sig).expect("boom deserialize signature");
        assert_eq!(deser_sig, sig);
    }

    #[test]
    #[should_panic]
    fn invalid_msg_agg() {
        let sk1 = SecretKey::random();
        let pk1 = sk1.public_key();
        let sk2 = SecretKey::random();
        let pk2 = sk2.public_key();

        let msg1 = b"Rip and tear";
        let msg2 = b"till is done";

        let msg3 = b"Nooooooo";

        let sig1 = sk1.sign(msg1);
        let sig2 = sk2.sign(msg2);

        if let Ok(agg_sig) = aggregate(&[sig1, sig2]) {
            // sig2 is over msg2 not msg3, expect test to fail
            if let Ok(res) = verify_messages(&agg_sig, &[msg1, msg3], &[pk1, pk2]) {
                assert!(res)
            } else {
                assert!(false)
            }
        } else {
            assert!(false)
        }
    }

    #[test]
    #[should_panic]
    fn invalid_sig_agg() {
        let sk1 = SecretKey::random();
        let pk1 = sk1.public_key();
        let sk2 = SecretKey::random();
        let pk2 = sk2.public_key();

        let msg1 = b"Rip and tear";
        let msg2 = b"till is done";

        let msg3 = b"Nooooooo";

        let sig1 = sk1.sign(msg1);
        let sig3 = sk2.sign(msg3);

        // Signature is over msg3, but msg2 is being checked
        if let Ok(agg_sig) = aggregate(&[sig1, sig3]) {
            if let Ok(res) = verify_messages(&agg_sig, &[msg1, msg2], &[pk1, pk2]) {
                assert!(res)
            } else {
                assert!(false)
            }
        } else {
            assert!(false)
        }
    }

    #[test]
    #[should_panic]
    fn invalid_pubkey_agg() {
        let sk1 = SecretKey::random();
        let pk1 = sk1.public_key();
        let sk2 = SecretKey::random();
        let _pk2 = sk2.public_key();
        let sk3 = SecretKey::random();
        let pk3 = sk3.public_key();

        let msg1 = b"Rip and tear";
        let msg2 = b"till is done";

        let sig1 = sk1.sign(msg1);
        let sig2 = sk2.sign(msg2);

        if let Ok(agg_sig) = aggregate(&[sig1, sig2]) {
            // pk3 is not for msg2, expect test to fail
            if let Ok(res) = verify_messages(&agg_sig, &[msg1, msg2], &[pk1, pk3]) {
                assert!(res)
            } else {
                assert!(false)
            }
        } else {
            assert!(false)
        }
    }

    #[test]
    #[should_panic]
    fn missing_pubkey_agg() {
        let sk1 = SecretKey::random();
        let pk1 = sk1.public_key();
        let sk2 = SecretKey::random();
        let _pk2 = sk2.public_key();

        let msg1 = b"Rip and tear";
        let msg2 = b"till is done";

        let sig1 = sk1.sign(msg1);
        let sig2 = sk2.sign(msg2);

        if let Ok(agg_sig) = aggregate(&[sig1, sig2]) {
            // pk2 is missing, expect test to fail
            if let Ok(res) = verify_messages(&agg_sig, &[msg1, msg2], &[pk1]) {
                assert!(res)
            } else {
                assert!(false)
            }
        } else {
            assert!(false)
        }
    }
}
