# TCG DICE Rust crate

a.k.a. `RICE`.

## Terminology

* `UDS`: Unique Device Secret. This is a per-device hardware-level secret accessible to the DICE but not accessible after the DICE runs.
* `CDI`: Compound Device Identifier. This value represents the hardware/software combination measured by the DICE. This is the DICE output and is passed to the software which has been measured. This is a secret.

## Definitions

### Hash Function

A hash function (e.g. SHA2-384):

`hash = H(input)`

### Key Derivation Function
`CDI = KDF(length, ikm, salt, info)`: Key Derivation Function. Output length is `length`. It takes an Initial Key Material (`ikm`), a [cryptographic salt](https://en.wikipedia.org/wiki/Salt_(cryptography)) and additional information `info`.

### Asymetric Key Pair Derivation Function

`PrivateKey, PublicKey = ASYM_KDF(input)`

which can be decomposed in:

1. `PrivateKey = KDF(N, input, KEY_SALT, "Key Pair")`
2. `PublicKey` is derived from `PrivateKey` depending on the chosen algorithm.

## DICE cycle

### Input

`InputValues` = `[Code, Config, Mode]` (for the loaded layer)

### CDI Generation

`CDI_1 = KDF(N, CDI_0, H(InputValues), "CDI")` where `CDI_0` is `UDS`.

`CDI_1_PrivateKey, CDI_1_PublicKey = ASYM_KDF(CDI_1)`

### CDI Certificate Generation

Subject = `CDI_1_Public`
Issuer = `CDI_0_Public`

### Output

`CDI_1` and `CDI_1_Certificat`

## References

[Open DICE](https://pigweed.googlesource.com/open-dice/+/HEAD/docs/specification.md)

[HKDF RFC](https://www.rfc-editor.org/rfc/rfc5869)

[HKDF Rust Crate](https://docs.rs/hkdf/latest/hkdf/)
