rust-tc
----

Simple threshold cryptography over BLS12-381 curve.

#### Example

```rust
    let sk = SecretKey::generate();
    // check secret key is non empty
    assert_ne!(SecretKey::from_scalar(Scalar::zero()), sk);
    // get associated public key from secret key
    let pk = sk.public_key();
    // some random msg we'll sign
    let msg = b"Rip and tear until it's done";
    // sign the msg with secret key
    let sig = sk.sign(msg);
    // verify the msg signature using public key
    assert!(pk.verify(&sig, msg))
```

#### Credits

The original [threshold_crypto](https://github.com/poanetwork/threshold_crypto) was written by poanetwork which is now not under active development.
