// SPDX-FileCopyrightText: 2023 Rivos Inc.
//
// SPDX-License-Identifier: Apache-2.0
use crate::Result;

use zeroize::Zeroize;

/// Compound Device Identifier (CDI) Types.
#[derive(Debug, Copy, Clone)]
pub enum CdiType {
    /// The attestation CDI.
    Attestation,

    /// The sealing CDI.
    Sealing,
}

impl CdiType {
    /// Transforms CdiType into a slice.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            CdiType::Attestation => b"CDI_Attestation",
            CdiType::Sealing => b"CDI_Sealing",
        }
    }
}

/// The CDI ID length.
/// The CDI ID is a fixed length derivation of the public key associated
/// with a CDI.
pub const CDI_ID_LEN: usize = 20;

/// Trait to implement a DICE Compound Device Identifier (CDI)
pub trait CompoundDeviceIdentifier: Zeroize + Sized {
    /// Returns the CDI Identifier based on the CDI public key.
    fn id(&self) -> Result<[u8; CDI_ID_LEN]>;
    /// Derives the next layer CDI and keypair for the current CDI, from a TCI
    /// and some additional context information.
    fn next(&self, info: Option<&[u8]>, next_tci: Option<&[u8]>) -> Result<Self>;
    /// Signs a message with the private key of the current CDI.
    fn sign(&self, msg: &[u8]) -> [u8; 64];
    /// Returns the public key of the current CDI.
    fn public_key(&self) -> [u8; 32];
}
