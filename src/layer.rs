// SPDX-FileCopyrightText: 2023 Rivos Inc.
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    cdi::{CdiType, CompoundDeviceIdentifier, CDI_ID_LEN},
    x509::{
        certificate::{Certificate, MAX_CERT_SIZE},
        request::CertReq,
    },
    Error, Result,
};

use arrayvec::ArrayVec;
use core::marker::PhantomData;
use digest::Digest;
use hkdf::HmacImpl;
use spin::RwLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A TCG DICE layer.
pub struct Layer<const N: usize, D: Digest, H: HmacImpl<D> = hmac::Hmac<D>> {
    cdi: CompoundDeviceIdentifier<N, D, H>,
    next_cdi: RwLock<Option<CompoundDeviceIdentifier<N, D, H>>>,

    _pd_d: PhantomData<D>,
    _pd_h: PhantomData<H>,
}

impl<const N: usize, D: Digest, H: HmacImpl<D>> Zeroize for Layer<N, D, H> {
    fn zeroize(&mut self) {
        self.cdi.zeroize();
        self.next_cdi.write().zeroize();
        self._pd_d.zeroize();
        self._pd_h.zeroize();
    }
}

impl<const N: usize, D: Digest, H: HmacImpl<D>> ZeroizeOnDrop for Layer<N, D, H> {}

impl<const N: usize, D: Digest, H: HmacImpl<D>> Layer<N, D, H> {
    /// DICE layer constructor.
    ///
    /// # Parameters
    /// @current_cdi: The current layer CDI.
    /// @cdi_type: The type of CDI
    pub fn new(current_cdi: &[u8], cdi_type: CdiType) -> Result<Self> {
        Ok(Layer {
            cdi: CompoundDeviceIdentifier::new(current_cdi, cdi_type)?,
            next_cdi: RwLock::new(None),
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

        Ok(())
    }

    /// The certificate DER for the next CDI.
    pub fn next_certificate<'a>(
        &self,
        extns: Option<&'a [&'a [u8]]>,
    ) -> Result<ArrayVec<u8, MAX_CERT_SIZE>> {
        let mut cert_der_bytes = [0u8; MAX_CERT_SIZE];
        let cert_der = Certificate::from_layer(
            &self.cdi,
            self.next_cdi.read().as_ref().ok_or(Error::MissingNextCdi)?,
            extns,
            &mut cert_der_bytes,
        )?;

        ArrayVec::try_from(cert_der).map_err(Error::CertificateTooLarge)
    }

    /// The certificate DER for the next CDI.
    pub fn csr_certificate<'a>(
        &self,
        csr: &'a CertReq<'a>,
        extns: Option<&'a [&'a [u8]]>,
    ) -> Result<ArrayVec<u8, MAX_CERT_SIZE>> {
        let mut cert_der_bytes = [0u8; MAX_CERT_SIZE];
        let cert_der = Certificate::from_csr(&self.cdi, csr, extns, &mut cert_der_bytes)?;

        ArrayVec::try_from(cert_der).map_err(Error::CertificateTooLarge)
    }

    /// Returns the current layer CDI ID.
    pub fn cdi_id(&self) -> Result<[u8; CDI_ID_LEN]> {
        self.cdi.id()
    }
}
