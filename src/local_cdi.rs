// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    cdi::{CdiType, CompoundDeviceIdentifier, CDI_ID_LEN},
    kdf::{derive_cdi_id, kdf},
    Error, Result,
};
use core::marker::PhantomData;
use digest::Digest;
use ed25519_dalek::{Keypair, SecretKey, Signature, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use hkdf::HmacImpl;
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// A DICE Compound Device Identifier (CDI) implementation.
pub struct LocalCdi<const N: usize, D: Digest, H: HmacImpl<D> = hmac::Hmac<D>> {
    cdi: [u8; N],
    cdi_type: CdiType,
    #[allow(dead_code)]
    key_pair: Keypair,

    _pd_d: PhantomData<D>,
    _pd_h: PhantomData<H>,
}

impl<const N: usize, D: Digest, H: HmacImpl<D>> Zeroize for LocalCdi<N, D, H> {
    fn zeroize(&mut self) {
        self.cdi.zeroize();
        self.key_pair.to_bytes().zeroize();
        self._pd_d.zeroize();
        self._pd_h.zeroize();
    }
}

impl<const N: usize, D: Digest, H: HmacImpl<D>> ZeroizeOnDrop for LocalCdi<N, D, H> {}

impl<const N: usize, D: Digest, H: HmacImpl<D>> LocalCdi<N, D, H> {
    /// DICE CDI constructor.
    ///
    /// # Parameters
    /// @current_cdi: The CDI buffer.
    /// @cdi_type: The type of CDI
    pub fn new(cdi_bytes: &[u8], cdi_type: CdiType) -> Result<Self> {
        let cdi = cdi_bytes.try_into().map_err(Error::InvalidCdi)?;
        let key_pair = key_pair_from_cdi::<D, H>(cdi_bytes)?;

        Ok(LocalCdi {
            cdi,
            cdi_type,
            key_pair,
            _pd_d: PhantomData,
            _pd_h: PhantomData,
        })
    }
}

impl<const N: usize, D: Digest, H: HmacImpl<D>> signature::Signer<Signature> for LocalCdi<N, D, H> {
    fn try_sign(&self, msg: &[u8]) -> core::result::Result<Signature, signature::Error> {
        self.key_pair.try_sign(msg)
    }
}

impl<const N: usize, D: Digest, H: HmacImpl<D>>
    CompoundDeviceIdentifier<PUBLIC_KEY_LENGTH, Signature> for LocalCdi<N, D, H>
{
    /// Derive the next layer CDI and keypair for the current CDI, from a TCI
    /// and some additional context information.
    ///
    /// # Parameters
    ///
    /// @info is the HKDF expansion additional context information.
    /// @tci is typically the next layer TCI. If None is passed, the ID_SALT salt is used.
    fn next(&self, info: Option<&[u8]>, next_tci: Option<&[u8]>) -> Result<Self> {
        let mut next_cdi: [u8; N] = [0; N];
        kdf::<D, H>(
            self.cdi.as_slice(),
            next_tci.unwrap_or(&ID_SALT),
            &[self.cdi_type.as_bytes(), info.unwrap_or(&[0u8; 0])],
            next_cdi.as_mut_slice(),
        )?;

        // Generate the key pair for the next CDI.
        let next_key_pair = key_pair_from_cdi::<D, H>(next_cdi.as_slice())?;

        Ok(LocalCdi {
            cdi: next_cdi,
            cdi_type: self.cdi_type,
            key_pair: next_key_pair,

            _pd_d: PhantomData,
            _pd_h: PhantomData,
        })
    }

    /// Public key for the current CDI.
    fn public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.key_pair.public.to_bytes()
    }

    /// CDI Identifier based on the CDI public key.
    fn id(&self) -> Result<[u8; CDI_ID_LEN]> {
        let mut cdi_id = [0u8; CDI_ID_LEN];
        derive_cdi_id::<D, H>(self.key_pair.public.as_bytes(), &mut cdi_id)?;

        Ok(cdi_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Signer;

    const CDI_LENGTH: usize = 32;

    #[test]
    fn local_cdi() {
        let cdi_bytes = [0u8; CDI_LENGTH];
        let msg = [1u8; 4096];
        let cdi =
            LocalCdi::<CDI_LENGTH, sha2::Sha384>::new(&cdi_bytes, CdiType::Attestation).unwrap();

        assert!(cdi.try_sign(&msg).is_ok());
        assert_eq!(
            cdi.sign(&msg).to_bytes().len(),
            ed25519_dalek::SIGNATURE_LENGTH
        );
    }
}
