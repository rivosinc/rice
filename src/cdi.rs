// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::{kdf::kdf, Error, Result};
use core::marker::PhantomData;
use digest::Digest;
use ed25519_dalek::{Keypair, SecretKey, SECRET_KEY_LENGTH};
use generic_array::{ArrayLength, GenericArray};
use hkdf::HmacImpl;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Compound Device Identifier (CDI) Types.
#[derive(Debug, Copy, Clone)]
pub enum CdiType {
    /// The attestation CDI.
    Attestation,

    /// The sealing CDI.
    Sealing,
}

impl CdiType {
    fn as_bytes(&self) -> &[u8] {
        match self {
            CdiType::Attestation => b"CDI_Attestation",
            CdiType::Sealing => b"CDI_Sealing",
        }
    }
}

// From the OpenDice implementation.
pub(crate) const ID_SALT: [u8; 64] = [
    0xDB, 0xDB, 0xAE, 0xBC, 0x80, 0x20, 0xDA, 0x9F, 0xF0, 0xDD, 0x5A, 0x24, 0xC8, 0x3A, 0xA5, 0xA5,
    0x42, 0x86, 0xDF, 0xC2, 0x63, 0x03, 0x1E, 0x32, 0x9B, 0x4D, 0xA1, 0x48, 0x43, 0x06, 0x59, 0xFE,
    0x62, 0xCD, 0xB5, 0xB7, 0xE1, 0xE0, 0x0F, 0xC6, 0x80, 0x30, 0x67, 0x11, 0xEB, 0x44, 0x4A, 0xF7,
    0x72, 0x09, 0x35, 0x94, 0x96, 0xFC, 0xFF, 0x1D, 0xB9, 0x52, 0x0B, 0xA5, 0x1C, 0x7B, 0x29, 0xEA,
];

// From the OpenDice implementation
pub(crate) const ASYM_SALT: [u8; 64] = [
    0x63, 0xB6, 0xA0, 0x4D, 0x2C, 0x07, 0x7F, 0xC1, 0x0F, 0x63, 0x9F, 0x21, 0xDA, 0x79, 0x38, 0x44,
    0x35, 0x6C, 0xC2, 0xB0, 0xB4, 0x41, 0xB3, 0xA7, 0x71, 0x24, 0x03, 0x5C, 0x03, 0xF8, 0xE1, 0xBE,
    0x60, 0x35, 0xD3, 0x1F, 0x28, 0x28, 0x21, 0xA7, 0x45, 0x0A, 0x02, 0x22, 0x2A, 0xB1, 0xB3, 0xCF,
    0xF1, 0x67, 0x9B, 0x05, 0xAB, 0x1C, 0xA5, 0xD1, 0xAF, 0xFB, 0x78, 0x9C, 0xCD, 0x2B, 0x0B, 0x3B,
];

/// The CDI ID length.
/// The CDI ID is a fixed length derivation of the public key associated
/// with a CDI.
pub const CDI_ID_LEN: usize = 20;

/// Extract and expand an asymetric key pair from a CDI.
fn key_pair_from_cdi<D: Digest, H: HmacImpl<D>>(cdi: &[u8]) -> Result<Keypair> {
    let mut private_key_bytes = [0u8; SECRET_KEY_LENGTH];
    kdf::<D, H>(cdi, &ASYM_SALT, &[b"Key_Pair"], &mut private_key_bytes)?;
    let secret = SecretKey::from_bytes(&private_key_bytes).map_err(Error::InvalidKey)?;
    Ok(Keypair {
        public: (&secret).into(),
        secret,
    })
}

/// A DICE Compound Device Identifier (CDI)
pub struct CompoundDeviceIdentifier<N: ArrayLength<u8>, D: Digest, H: HmacImpl<D> = hmac::Hmac<D>> {
    cdi: GenericArray<u8, N>,
    cdi_type: CdiType,
    #[allow(dead_code)]
    key_pair: Keypair,

    _pd_d: PhantomData<D>,
    _pd_h: PhantomData<H>,
}

impl<N: ArrayLength<u8>, D: Digest, H: HmacImpl<D>> Zeroize for CompoundDeviceIdentifier<N, D, H> {
    fn zeroize(&mut self) {
        self.cdi.zeroize();
        self.key_pair.to_bytes().zeroize();
        self._pd_d.zeroize();
        self._pd_h.zeroize();
    }
}

impl<N: ArrayLength<u8>, D: Digest, H: HmacImpl<D>> ZeroizeOnDrop
    for CompoundDeviceIdentifier<N, D, H>
{
}

impl<N: ArrayLength<u8>, D: Digest, H: HmacImpl<D>> CompoundDeviceIdentifier<N, D, H> {
    /// DICE CDI constructor.
    ///
    /// # Parameters
    /// @current_cdi: The CDI buffer.
    /// @cdi_type: The type of CDI
    pub fn new(cdi_bytes: &[u8], cdi_type: CdiType) -> Result<Self> {
        let cdi = GenericArray::clone_from_slice(cdi_bytes);
        let key_pair = key_pair_from_cdi::<D, H>(cdi_bytes)?;

        Ok(CompoundDeviceIdentifier {
            cdi,
            cdi_type,
            key_pair,
            _pd_d: PhantomData,
            _pd_h: PhantomData,
        })
    }

    /// Derive the next layer CDI and keypair for the current CDI, from a TCI
    /// and some additional context information.
    ///
    /// # Parameters
    ///
    /// @info is the HKDF expansion additional context information.
    /// @tci is typically the next layer TCI. If None is passed, the ID_SALT salt is used.
    pub fn next(&self, info: Option<&[u8]>, next_tci: Option<&[u8]>) -> Result<Self> {
        let mut next_cdi: GenericArray<u8, N> = GenericArray::default();
        kdf::<D, H>(
            self.cdi.as_slice(),
            next_tci.unwrap_or(&ID_SALT),
            &[self.cdi_type.as_bytes(), info.unwrap_or(&[0u8; 0])],
            next_cdi.as_mut_slice(),
        )?;

        // Generate the key pair for the next CDI.
        let next_key_pair = key_pair_from_cdi::<D, H>(next_cdi.as_slice())?;

        Ok(CompoundDeviceIdentifier {
            cdi: next_cdi,
            cdi_type: self.cdi_type,
            key_pair: next_key_pair,

            _pd_d: PhantomData,
            _pd_h: PhantomData,
        })
    }

    /// The ED25519 key pair for the CDI
    pub fn key_pair(&self) -> &Keypair {
        &self.key_pair
    }

    /// CDI Identifier based on the CDI public key.
    pub fn id(&self) -> Result<[u8; CDI_ID_LEN]> {
        let mut cdi_id = [0u8; CDI_ID_LEN];
        kdf::<D, H>(
            self.key_pair.public.as_bytes(),
            &ID_SALT,
            &[b"CDI_ID"],
            &mut cdi_id,
        )?;

        Ok(cdi_id)
    }
}
