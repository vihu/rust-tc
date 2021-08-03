use crate::{ciphertext::Ciphertext, sig::Signature, util, util::hash_g2};
use bls12_381::{pairing, G1Affine, G2Affine, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use rand::RngCore;
use std::cmp::PartialEq;
use subtle::{Choice, ConstantTimeEq};

const PKSIZE: usize = 48;

/// A public key.
#[derive(Copy, Clone, Debug, Eq)]
pub struct PublicKey(pub G1Affine);

impl PublicKey {
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &Signature, msg: M) -> bool {
        let gt1 = pairing(&G1Affine::generator(), &sig.0);
        let gt2 = pairing(&self.0, &hash_g2(msg));
        gt1 == gt2
    }

    pub fn is_valid(&self) -> bool {
        self.0.to_compressed().len() == PKSIZE
    }

    pub fn encrypt<M: AsRef<[u8]>>(&self, msg: M) -> Ciphertext {
        self.encrypt_with_rng(&mut OsRng, msg)
    }

    /// Encrypts the message.
    pub fn encrypt_with_rng<R: RngCore, M: AsRef<[u8]>>(&self, rng: &mut R, msg: M) -> Ciphertext {
        let r: Scalar = Scalar::random(rng);
        let u = G1Affine::from(G1Affine::generator() * r);
        let v: Vec<u8> = {
            let g = G1Affine::from(self.0 * r);
            util::xor_with_hash(g, msg.as_ref())
        };
        let w = G2Affine::from(util::hash_g1_g2(u, &v) * r);
        Ciphertext(u, v, w)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl ConstantTimeEq for PublicKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::sk::SecretKey;
    // use rand::{thread_rng, Rng};

    // TODO: Fix me
    // #[test]
    // fn test_equality() {
    //     let bytes = thread_rng().gen::<[u8; 32]>();
    //     let sk1: SecretKey = SecretKey::from_bytes(&bytes);
    //     let pk1 = sk1.public_key();
    //     let sk2: SecretKey = SecretKey::from_bytes(&bytes);
    //     let pk2 = sk2.public_key();
    //     println!("sk1: {:?}", sk1);
    //     println!("pk1: {:?}", pk1);
    //     println!("sk2: {:?}", sk2);
    //     println!("pk2: {:?}", pk2);
    //     // println!("eq?: {:?}", pk1 == pk2);
    // }

    #[test]
    fn valid() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        assert!(pk.is_valid())
    }

    #[test]
    fn enc_dec() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        let msg = b"Rip and tear, until it's done";
        let encrypted = pk.encrypt(msg);
        assert!(encrypted.verify());
        if let Some(decrypted) = sk.decrypt(&encrypted) {
            assert_eq!(decrypted, msg)
        } else {
            assert!(false)
        }
    }

    #[test]
    #[should_panic]
    fn other_sk_enc_dec() {
        let sk = SecretKey::random();
        let other_sk = SecretKey::random();
        let pk = sk.public_key();
        let msg = b"Rip and tear, until it's done";
        let encrypted = pk.encrypt(msg);
        assert!(encrypted.verify());
        if let Some(decrypted) = other_sk.decrypt(&encrypted) {
            assert_eq!(decrypted, msg)
        } else {
            assert!(false)
        }
    }

    #[test]
    #[should_panic]
    fn other_msg_enc_dec() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        let msg = b"Rip and tear, until it's done";
        let other_msg = b"Don't Rip and tear, until it's done";
        let encrypted = pk.encrypt(msg);
        assert!(encrypted.verify());
        if let Some(decrypted) = sk.decrypt(&encrypted) {
            assert_eq!(decrypted, other_msg)
        } else {
            assert!(false)
        }
    }
}
