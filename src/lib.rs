// SPDX-FileCopyrightText: 2023 Rivos Inc.
//
// SPDX-License-Identifier: Apache-2.0

//! Pure Rust, heapless attestation crate.
#![no_std]

/// Rice errors
#[derive(Debug)]
pub enum Error {
    /// Generated certificate is too large
    CertificateTooLarge(arrayvec::CapacityError),

    /// Invalid CDI
    InvalidCdi(core::array::TryFromSliceError),

    /// Failed to expand the CDI
    InvalidCdiExpansion(hkdf::InvalidLength),

    /// Invalid CDI ID
    InvalidCdiId(hex::FromHexError),

    /// Invalid CSR
    InvalidCertReq(der::Error),

    /// Invalid DER payload
    InvalidDer(der::Error),

    /// Invalid data digest
    InvalidDigest(der::Error),

    /// Invalid X.509 extension DER
    InvalidExtensionDer(der::Error),

    /// Invalid public key bytes
    InvalidPublicKey,

    /// Invalid public key DER
    InvalidPublicKeyDer(spki::Error),

    /// Invalid digital signature
    InvalidSignature,

    /// Invalid X.509 TCB info extension DER
    InvalidTcbInfoExtensionDer(der::Error),

    /// Failed to expand the extracted key
    InvalidExpansion(hkdf::InvalidLength),

    /// Invalid Key bytes
    InvalidKey(ed25519_dalek::SignatureError),

    /// Next CDI is not generated
    MissingNextCdi,

    /// Unsupported signing algorithm
    UnsupportedAlgorithm(const_oid::ObjectIdentifier),
}

/// Custom DICE result.
pub type Result<T> = core::result::Result<T, Error>;

/// The DICE Compound Device Identifier (CDI) interface.
pub mod cdi;

/// The DICE layer module
pub mod layer;

/// Key Derivation Function module
pub mod kdf;

/// X.509 certificate module
pub mod x509;

/// Local CDI implementation module.
pub mod local_cdi;
