// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    cdi::{CdiType, CompoundDeviceIdentifier},
    x509::certificate::{Certificate, MAX_CERT_SIZE},
    Error, Result,
};

use arrayvec::ArrayVec;
use core::marker::PhantomData;
use digest::Digest;
use generic_array::ArrayLength;
use hkdf::HmacImpl;
use spin::RwLock;

/// A TCG DICE layer.
pub struct Layer<N: ArrayLength<u8>, D: Digest, H: HmacImpl<D> = hmac::Hmac<D>> {
    cdi: CompoundDeviceIdentifier<N, D, H>,
    next_cdi: RwLock<Option<CompoundDeviceIdentifier<N, D, H>>>,
    next_certificate: RwLock<ArrayVec<u8, MAX_CERT_SIZE>>,

    _pd_d: PhantomData<D>,
    _pd_h: PhantomData<H>,
}

impl<N: ArrayLength<u8>, D: Digest, H: HmacImpl<D>> Layer<N, D, H> {
    /// DICE layer constructor.
    ///
    /// # Parameters
    /// @current_cdi: The current layer CDI.
    /// @cdi_type: The type of CDI
    pub fn new(current_cdi: &[u8], cdi_type: CdiType) -> Result<Self> {
        Ok(Layer {
            cdi: CompoundDeviceIdentifier::new(current_cdi, cdi_type)?,
            next_cdi: RwLock::new(None),
            next_certificate: RwLock::new(ArrayVec::<u8, MAX_CERT_SIZE>::new()),
            _pd_d: PhantomData,
            _pd_h: PhantomData,
        })
    }

    /// Roll the DICE and derive the next layer CDI and keypair from the
    /// current CDI.
    ///
    /// # Parameters
    ///
    /// @info is the HKDF expansion additional context information.
    /// @tci is the next layer TCI. If None is passed, the ID_SALT salt is used.
    pub fn roll(&self, info: Option<&[u8]>, next_tci: Option<&[u8]>) -> Result<()> {
        self.next_cdi
            .write()
            .replace(self.cdi.next(info, next_tci)?);

        let mut cert_der_bytes = [0u8; MAX_CERT_SIZE];
        let cert_der = Certificate::from_layer(
            &self.cdi,
            self.next_cdi.read().as_ref().ok_or(Error::MissingNextCdi)?,
            &mut cert_der_bytes,
        )?;

        *self.next_certificate.write() =
            ArrayVec::try_from(cert_der).map_err(Error::CertificateTooLarge)?;

        Ok(())
    }

    /// The certificate DER for the next CDI.
    pub fn next_certificate(&self) -> ArrayVec<u8, MAX_CERT_SIZE> {
        self.next_certificate.read().clone()
    }
}
